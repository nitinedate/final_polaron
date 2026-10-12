"""Resource-aware sidecar scheduler for independent forensic work."""
from __future__ import annotations

import json, uuid, os
from app.db.sql_helpers import execute, fetchone


def cpu_sidecar_headroom():
    cpu_max=float(os.environ.get('SIDECAR_CPU_MAX_PCT','88') or 88); mem_max=float(os.environ.get('SIDECAR_MEMORY_MAX_PCT','88') or 88)
    try:
        import psutil
        cpu=float(psutil.cpu_percent(interval=0.05)); mem=float(psutil.virtual_memory().percent)
        return cpu < cpu_max and mem < mem_max, {'cpu_pct':cpu,'memory_pct':mem}
    except Exception:
        return False, {'cpu_pct':None,'memory_pct':None}


def ensure_sidecar_schema(db):
    execute(db,"""CREATE TABLE IF NOT EXISTS pipeline_sidecar_runs(
        job_id uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
        sidecar text NOT NULL,status text NOT NULL DEFAULT 'pending',task_id text,
        heartbeat_at timestamptz,updated_at timestamptz NOT NULL DEFAULT NOW(),details jsonb NOT NULL DEFAULT '{}'::jsonb,
        PRIMARY KEY(job_id,sidecar))""")
    execute(db,"CREATE INDEX IF NOT EXISTS ix_pipeline_sidecar_status ON pipeline_sidecar_runs(status,updated_at)")


def claim_sidecar(db,job_id,sidecar,*,details=None):
    ensure_sidecar_schema(db)
    details = details or {}
    tid=str(uuid.uuid4())
    claimed = fetchone(db,"""INSERT INTO pipeline_sidecar_runs(job_id,sidecar,status,task_id,heartbeat_at,updated_at,details)
      SELECT :jid,:s,'queued',:tid,NOW(),NOW(),CAST(:d AS jsonb)
      WHERE EXISTS (SELECT 1 FROM pipeline_stage_runs WHERE job_id=:jid
        AND stage=:active AND status='running')
      ON CONFLICT(job_id,sidecar) DO UPDATE SET status='queued',task_id=EXCLUDED.task_id,
        heartbeat_at=NOW(),updated_at=NOW(),details=EXCLUDED.details
      WHERE pipeline_sidecar_runs.status NOT IN ('queued','running')
        AND NOT (pipeline_sidecar_runs.status='done' AND
          COALESCE(pipeline_sidecar_runs.details->>'parallel_with','')=
          COALESCE(EXCLUDED.details->>'parallel_with',''))
      RETURNING task_id""", {'jid':job_id,'s':sidecar,'tid':tid,'d':json.dumps(details),'active':details.get('parallel_with')})
    db.commit()
    return str(claimed['task_id']) if claimed else None


def finish_sidecar(db,job_id,sidecar,task_id,*,status='done',details=None):
    execute(db,"""UPDATE pipeline_sidecar_runs SET status=:st,heartbeat_at=NOW(),updated_at=NOW(),details=coalesce(details,'{}'::jsonb)||CAST(:d AS jsonb)
      WHERE job_id=:jid AND sidecar=:s AND task_id=:tid""",{'st':status,'jid':job_id,'s':sidecar,'tid':task_id,'d':json.dumps(details or {})});db.commit()




def sidecar_slot(reason: str):
    """Shared ten-slot distributed admission control for independent CPU/DB helpers."""
    from app.services.adaptive_semaphore import acquire_resource_slot
    from app.services.forensic_serial_policy import PIPELINE_PARALLEL_SLOTS
    return acquire_resource_slot(
        "forensic-pipeline-cpu", reason=reason, wait_sec=20.0, ttl_sec=900,
        requested_limit=PIPELINE_PARALLEL_SLOTS, fail_closed=True, fail_open_if_unavailable=False,
    )


def defer_sidecar_if_busy(task, exc) -> None:
    """Retry a sidecar that found every CPU slot taken.

    A full pool is temporary.  Marking the sidecar failed makes the progress
    monitor launch a new attempt immediately, which fills the worker and the
    slot table again.  Retry the same delivery instead.
    """
    from celery.exceptions import MaxRetriesExceededError, Retry

    from app.services.adaptive_semaphore import ResourceSemaphoreTimeout

    try:
        task.retry(exc=exc, countdown=15, max_retries=40)
    except Retry:
        raise
    except (MaxRetriesExceededError, ResourceSemaphoreTimeout):
        return

# Legacy V67 guard was: active_stage not in {'recovery','ocr','media_review'}
# Legacy V68 prechunk guard was: if active_stage in {'ocr','media_review'}:
# Legacy V68 leakage guard was: if active_stage in {'recovery','ocr'}:
# V71 intentionally broadens these after dependency analysis and slot admission.
def schedule_safe_sidecars(db,job_id,*,schema_name,active_stage):
    """Run dependency-independent CPU/DB helpers beside the owning stage.

    The authoritative stage remains serial for evidential ordering. Independent
    derived work is admitted under a per-job ten-slot budget so parsing, recovery,
    OCR preparation, leakage correlation, inventory and RAG preparation can overlap
    without allowing two source writers or two CUDA owners to compete.
    """
    from app.forensic_common.pipeline_routing import parse_queue, rag_prep_queue
    from app.tasks import company_leakage_sidecar_task, prechunk_sidecar_task, artifact_inventory_sidecar_task
    from app.services.forensic_serial_policy import PIPELINE_PARALLEL_SLOTS
    queued=[]
    if active_stage not in {'parse','recovery','ocr','media_review','inventory','chunk'}:
        return {'queued':queued}
    admitted, resources = cpu_sidecar_headroom()
    if not admitted:
        return {'queued':queued,'status':'deferred_for_resources','resources':resources}
    ensure_sidecar_schema(db)
    active_count=int((fetchone(db, "SELECT count(*) AS c FROM pipeline_sidecar_runs WHERE job_id=:jid AND status IN ('queued','running')", {'jid':job_id}) or {}).get('c') or 0)
    available=max(0, PIPELINE_PARALLEL_SLOTS-active_count)
    if available<=0:
        return {'queued':queued,'status':'parallel_budget_full','slots':PIPELINE_PARALLEL_SLOTS}

    def launch(name, task, queue, token):
        nonlocal available
        if available<=0:
            return
        tid=claim_sidecar(db,job_id,name,details={'parallel_with':token,'slot_budget':PIPELINE_PARALLEL_SLOTS})
        if tid:
            task.apply_async(args=(schema_name,job_id,tid),queue=queue,task_id=tid)
            queued.append(name); available-=1

    # Prechunk consumes only already-parsed text; it is safe from parse onward.
    if active_stage in {'parse','recovery','ocr','media_review','inventory'}:
        launch('prechunk', prechunk_sidecar_task, rag_prep_queue(), active_stage)
    # Leakage analysis is incremental/idempotent and can scan the parsed delta.
    # Keep the recovery/OCR branch explicit because these are the highest-value
    # overlaps on long forensic jobs.
    if active_stage in {'recovery','ocr'} and available > 0:
        tid=claim_sidecar(db,job_id,'company_leakage',details={'parallel_with':active_stage,'slot_budget':PIPELINE_PARALLEL_SLOTS})
        if tid:
            company_leakage_sidecar_task.apply_async(args=(schema_name,job_id,tid),queue=parse_queue(),task_id=tid)
            queued.append('company_leakage'); available-=1
    elif active_stage in {'parse','media_review'}:
        launch('company_leakage', company_leakage_sidecar_task, parse_queue(), active_stage)
    # Inventory is DB/CPU work and is useful while CUDA owns OCR.
    if active_stage=='ocr':
        launch('artifact_inventory', artifact_inventory_sidecar_task, parse_queue(), active_stage)
    return {'queued':queued,'slots':PIPELINE_PARALLEL_SLOTS,'available_after':available,'resources':resources}


from contextlib import contextmanager

@contextmanager
def sidecar_execution(db, job_id, sidecar, task_id, *, schema_name):
    """One owner per tenant/job/sidecar; stale or duplicate deliveries do no work."""
    from app.services.forensic_serial_pipeline import pipeline_execution_lock
    with pipeline_execution_lock(db, schema_name, f'sidecar:{job_id}:{sidecar}') as acquired:
        if not acquired:
            yield False
            return
        row = fetchone(db, """SELECT status,task_id FROM pipeline_sidecar_runs
            WHERE job_id=:jid AND sidecar=:sidecar FOR UPDATE""",
            {'jid':job_id,'sidecar':sidecar})
        if not row or str(row.get('task_id')) != str(task_id) or row['status'] not in {'queued','running'}:
            db.rollback()
            yield False
            return
        execute(db, """UPDATE pipeline_sidecar_runs SET status='running',heartbeat_at=NOW(),updated_at=NOW()
            WHERE job_id=:jid AND sidecar=:sidecar AND task_id=:tid""",
            {'jid':job_id,'sidecar':sidecar,'tid':task_id})
        db.commit()
        yield True

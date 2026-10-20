# OCR worker queue blockage: focused monitoring correction

## Observed case
Screenshot shows first six stages complete, OCR queued 0/5, and `No responding consumer for ocr`. The source routes forensic OCR to queue `ocr`; `worker-ocr-gpu` is configured as its consumer.

## Changes
- `progress_agent.queue_delivery_state()` differentiates confirmed missing queue consumer (`blocked`) from broker inspection unavailable (`valid_wait`, not a false absence).
- Provides worker name, queue name and corrective hints; does not drop/revoke queued tasks, mutate manifests, re-extract or mark OCR complete.
- No change to the one-authoritative-stage-per-job invariant. Existing parallel sidecars are retained.

## On Windows host (from repository root)
```powershell
docker compose config --services | Select-String 'redis|worker-ocr-gpu|worker-progress'
docker compose ps redis worker-ocr-gpu worker-progress
docker compose logs --tail 150 worker-ocr-gpu
docker compose exec worker-progress celery -A app.celery_app.celery inspect active_queues
```

If `worker-ocr-gpu` is stopped or missing:
```powershell
docker compose up -d --no-deps worker-ocr-gpu
```

If the worker fails due to CUDA/NVIDIA configuration, repair GPU runtime and re-create the OCR worker; do not delete messages. Its compose currently requests `gpus: all` even when OCR_ENGINE=tesseract. A CPU Tesseract profile is possible, but not automatically activated by this patch.

## Deployment
The patch is source code. Deploy it in the forensic progress-agent's `/app` code and restart ONLY the progress worker after verifying appropriate compose service names. The OCR worker itself still must be made healthy before OCR will execute. Check broker connectivity, correct broker URL, and that Celery tasks are registered.

## Parallelism
`safe_parallel.py` already schedules parse shard, OCR, prechunk, leakage, graph-file sidecars using resource-aware claims. Do not relax the unique active authoritative-stage index; overlap independently claimed, committed artifact partitions instead. RAG finalization must await OCR/media result barriers.

## Validation
`python -m py_compile` passed; three focused unit checks passed. No Docker/GPU/MinIO live-run validation possible in this environment.

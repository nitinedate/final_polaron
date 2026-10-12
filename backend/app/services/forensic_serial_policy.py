"""Disk/Mobile policy: dependency-safe stages with up to ten independent evidence units."""

from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, ThreadPoolExecutor, wait
from contextlib import contextmanager
from contextvars import ContextVar
from threading import BoundedSemaphore
import multiprocessing
import os

# File-level workers are independent evidence units. Keep one authoritative stage
# writer, but permit more CPU readers/parsers on capable hosts. The ceiling can be
# tuned without code changes and remains bounded to avoid DB/thermal collapse.
_CPU_COUNT = max(int(os.cpu_count() or 4), 1)
MAX_PARALLELISM = max(2, min(int(os.environ.get("FORENSIC_MAX_PARALLELISM", min(10, _CPU_COUNT)) or 10), 16))
# One job may have several independent CPU/DB helpers, but the shared evidence
# pipeline never admits more than this many concurrent units by default.
PIPELINE_PARALLEL_SLOTS = max(2, min(int(os.environ.get("PIPELINE_PARALLEL_SLOTS", "10") or 10), 16))
# Character windows for complete forensic evidence, including any source header.
CHUNK_SIZE = 3000
CHUNK_OVERLAP = 800
CHUNK_POLICY = "chars-3000-overlap-800-v3"
# A finished file keeps its previous window. A size change must not rechunk it.
ACCEPTED_CHUNK_POLICIES = (CHUNK_POLICY, "chars-2500-overlap-800-v2")
_stage_context: ContextVar[str | None] = ContextVar(
    "forensic_serial_stage", default=None
)


def serial_enabled() -> bool:
    # This policy is deliberately unrelated to PERF_POLICY_MODE or the scanner.
    from app.service_identity import VULN, current_service

    return current_service() != VULN


def parallelism(requested: int = MAX_PARALLELISM) -> int:
    return max(1, min(MAX_PARALLELISM, int(requested or 1)))


def chunk_policy_accepted_sql(expr: str = "COALESCE(metadata->>'serial_chunk_policy','')") -> str:
    values = ",".join(f"'{policy}'" for policy in ACCEPTED_CHUNK_POLICIES)
    return f"{expr} IN ({values})"


def current_stage() -> str | None:
    return _stage_context.get()


@contextmanager
def stage_context(stage: str):
    token = _stage_context.set(stage)
    try:
        yield
    finally:
        _stage_context.reset(token)


def bounded_map(fn, items, *, workers: int = MAX_PARALLELISM):
    """Bound both running work and queued inputs; never submit the whole evidence set.

    Database Sessions must be created inside fn, never shared across these threads.
    Exceptions propagate at the barrier after the executor joins its workers.
    """
    slots = parallelism(workers)
    gate = BoundedSemaphore(slots)
    source = iter(items)

    def run(item):
        with gate:
            return fn(item)

    with ThreadPoolExecutor(
        max_workers=slots, thread_name_prefix="forensic-stage"
    ) as pool:
        pending = set()
        exhausted = False
        while pending or not exhausted:
            while len(pending) < slots and not exhausted:
                try:
                    pending.add(pool.submit(run, next(source)))
                except StopIteration:
                    exhausted = True
            if not pending:
                break
            finished, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in finished:
                yield future.result()


def bounded_process_map(fn, items, *, workers: int = MAX_PARALLELISM):
    """Parallelize pure CPU work without sharing DB sessions or CUDA contexts.

    Stage workers are normal subprocesses and can use a spawn process pool. If a
    caller is ever executed from a daemonic process, fall back to threads rather
    than failing with "daemonic processes are not allowed to have children".
    Inputs and outputs must be picklable and database access must stay outside fn.
    """
    slots = parallelism(workers)
    source = iter(items)
    executor_cls = ThreadPoolExecutor if multiprocessing.current_process().daemon else ProcessPoolExecutor
    kwargs = {"max_workers": slots}
    if executor_cls is ProcessPoolExecutor:
        kwargs["mp_context"] = multiprocessing.get_context("spawn")
    else:
        kwargs["thread_name_prefix"] = "forensic-cpu"
    with executor_cls(**kwargs) as pool:
        pending = set()
        exhausted = False
        while pending or not exhausted:
            while len(pending) < slots and not exhausted:
                try:
                    pending.add(pool.submit(fn, next(source)))
                except StopIteration:
                    exhausted = True
            if not pending:
                break
            finished, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in finished:
                yield future.result()


def shard_overlap_enabled() -> bool:
    """Opt-in until verified against real extraction and PostgreSQL integration."""
    return os.environ.get("FORENSIC_STREAM_SHARD_OVERLAP", "false").strip().lower() in {"1", "true", "yes"}

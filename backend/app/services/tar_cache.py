"""Cached tar shard reader — streams zstd tar parts without loading whole archives."""

from __future__ import annotations

import io
import logging
import tarfile
import threading
import time
from collections import OrderedDict
from collections.abc import Iterator

import zstandard as zstd

from app.services.storage import open_object_stream

log = logging.getLogger("tar_cache")

_CACHE_MAX = 8
_MAX_CACHED_FILE_BYTES = 10_000_000
_lock = threading.Lock()
_cache: OrderedDict[str, dict[str, bytes | None]] = OrderedDict()


def _decompress_zstd(raw: bytes) -> bytes | None:
    """Decompress single-frame zstd blobs (e.g. index.jsonl.zst)."""
    if not raw:
        return None
    try:
        return zstd.ZstdDecompressor().decompress(raw)
    except zstd.ZstdError:
        return None


def _cache_file(part_uri: str, path: str, content: bytes | None) -> None:
    if content is None or len(content) > _MAX_CACHED_FILE_BYTES:
        return
    with _lock:
        bucket = _cache.setdefault(part_uri, {})
        bucket[path] = content
        _cache.move_to_end(part_uri)
        while len(_cache) > _CACHE_MAX:
            _cache.popitem(last=False)


def _cached_file(part_uri: str, path: str) -> bytes | None:
    with _lock:
        bucket = _cache.get(part_uri)
        if bucket is not None and path in bucket:
            _cache.move_to_end(part_uri)
            return bucket[path]
    return None


def iter_files_from_part(
    part_uri: str,
    paths: set[str],
    *,
    max_bytes: int | None = None,
    max_bytes_by_path: dict[str, int | None] | None = None,
    on_progress=None,
) -> Iterator[tuple[str, bytes | None]]:
    """Yield ``(path, content)`` for wanted members via streamed MinIO/zstd/tar.

    Never buffers the compressed shard in RAM (parts can be 5–13+ GB).
    ``max_bytes_by_path`` applies a per-file cap in one pass so callers do not
    decompress the same shard once for every read budget. ``on_progress`` is
    ``(members_scanned, files_yielded)`` and lets a long scan stay alive.
    """
    wanted = {p.replace("\\", "/") for p in paths}
    if not wanted:
        return

    # Serve tiny cache hits first without touching the stream.
    remaining = set(wanted)
    for p in list(remaining):
        if max_bytes is None:
            hit = _cached_file(part_uri, p)
            if hit is not None:
                remaining.discard(p)
                yield p, hit
        else:
            cached = _cached_file(part_uri, p)
            if cached is not None:
                remaining.discard(p)
                yield p, cached[:max_bytes]
    if not remaining:
        return

    stream = open_object_stream(part_uri)
    if stream is None:
        for p in remaining:
            yield p, None
        return

    scanned = 0
    yielded = 0
    last_progress = time.monotonic()

    def _note(force: bool = False) -> None:
        nonlocal last_progress
        if on_progress is None:
            return
        now = time.monotonic()
        if not force and (now - last_progress) < 5.0 and scanned % 400 != 0:
            return
        last_progress = now
        try:
            on_progress(scanned, yielded)
        except Exception:
            log.debug("Shard scan progress callback failed", exc_info=True)

    try:
        dctx = zstd.ZstdDecompressor()
        with dctx.stream_reader(stream) as zreader:
            with tarfile.open(fileobj=zreader, mode="r|") as tar:
                for member in tar:
                    if not remaining:
                        break
                    scanned += 1
                    if scanned == 1 or scanned % 200 == 0:
                        _note()
                    if not member.isfile():
                        continue
                    norm = member.name.replace("\\", "/")
                    if norm not in remaining:
                        continue
                    f = tar.extractfile(member)
                    if not f:
                        remaining.discard(norm)
                        yielded += 1
                        yield norm, None
                        continue
                    cap = max_bytes
                    if max_bytes_by_path is not None:
                        cap = max_bytes_by_path.get(norm, max_bytes)
                    content = f.read(cap) if cap else f.read()
                    if cap is None:
                        _cache_file(part_uri, norm, content)
                    remaining.discard(norm)
                    yielded += 1
                    yield norm, content
        _note(force=True)
    except Exception as exc:
        # A stage cancel is raised on the main thread from SIGTERM. Do not treat
        # it as a short read and keep parsing the rest of the shard.
        if type(exc).__name__ == "StageWaiting":
            raise
        log.warning("Streamed tar read failed part=%s: %s", part_uri, exc)
    finally:
        try:
            stream.close()
        except Exception:
            pass

    for p in remaining:
        yield p, None


def iter_spilled_files_from_part(part_uri: str, paths: set[str], *, directory: str | None = None):
    """Stream wanted members to temp files in one shard pass.

    Callers review one file and delete it before the next member is read, so a
    shard is decompressed once instead of once per picture.
    """
    import os
    import tempfile

    wanted = {p.replace("\\", "/") for p in paths}
    if not wanted:
        return
    stream = open_object_stream(part_uri)
    if stream is None:
        return
    try:
        dctx = zstd.ZstdDecompressor()
        with dctx.stream_reader(stream) as zreader:
            with tarfile.open(fileobj=zreader, mode="r|") as tar:
                for member in tar:
                    if not wanted:
                        break
                    if not member.isfile():
                        continue
                    norm = member.name.replace("\\", "/")
                    if norm not in wanted:
                        continue
                    handle = tar.extractfile(member)
                    if handle is None:
                        wanted.discard(norm)
                        yield norm, None
                        continue
                    suffix = os.path.splitext(norm)[1][:16]
                    tmp = tempfile.NamedTemporaryFile(
                        prefix="aetheris-media-",
                        suffix=suffix,
                        dir=directory or "/tmp",
                        delete=False,
                    )
                    try:
                        while True:
                            chunk = handle.read(1024 * 1024)
                            if not chunk:
                                break
                            tmp.write(chunk)
                        tmp.flush()
                    except Exception:
                        tmp.close()
                        os.unlink(tmp.name)
                        raise
                    tmp.close()
                    wanted.discard(norm)
                    yield norm, tmp.name
    except Exception as exc:
        if type(exc).__name__ == "StageWaiting":
            raise
        log.warning("Streamed tar spill failed part=%s: %s", part_uri, exc)
    finally:
        try:
            stream.close()
        except Exception:
            pass


def read_file_from_part(part_uri: str, path: str, *, max_bytes: int | None = None) -> bytes | None:
    """Read a single file from a tar shard (streaming — low memory)."""
    for _norm, content in iter_files_from_part(part_uri, {path}, max_bytes=max_bytes):
        return content
    return None


def read_files_from_part(
    part_uri: str,
    paths: set[str],
    *,
    max_bytes: int | None = None,
) -> dict[str, bytes | None]:
    """Read many paths from one shard in a single streaming pass.

    Prefer :func:`iter_files_from_part` when callers can process members
    incrementally — this helper still materializes the full result dict.
    """
    wanted = {p.replace("\\", "/") for p in paths}
    found: dict[str, bytes | None] = {p: None for p in wanted}
    for norm, content in iter_files_from_part(part_uri, wanted, max_bytes=max_bytes):
        found[norm] = content
    return found


def clear_tar_cache() -> None:
    with _lock:
        _cache.clear()

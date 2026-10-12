"""Indexes that keep Artifacts / Evidence / family Open off sequential scans.

Hot paths (measured on ~130k job_artifacts rows):
  * list ChatStorage / msgstore by lower(file_name)
  * ILIKE '%ChatStorage%' / '%msgstore.db%' on file_path
  * artifact_parse_results JOIN job_artifacts by job + parser_name
  * exact file_name media lookups
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.db.sql_helpers import execute

log = logging.getLogger("evidence_browse_indexes")

_READY: set[int] = set()

# B-tree / expression indexes that do not need pg_trgm. Safe to run on every
# first browse of a firm schema (IF NOT EXISTS is cheap after the first build).
_BROWSE_INDEX_SQL = (
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_file_name_lower
        ON job_artifacts (job_id, lower(file_name))
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_path
        ON job_artifacts (job_id, file_path)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_size
        ON job_artifacts (job_id, size_bytes DESC NULLS LAST)
    """,
    # Cover WhatsApp store picks: job_id filter + ORDER BY size_bytes.
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_name_size
        ON job_artifacts (job_id, lower(file_name), size_bytes DESC NULLS LAST)
    """,
    # Media resolve: exact basename match under a job (Open / Download path).
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_file_name
        ON job_artifacts (job_id, file_name)
    """,
    # Path-prefix / LIKE '%tail' helpers for recovered Media/… lookups.
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_path_lower
        ON job_artifacts (job_id, lower(file_path))
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_artifact_parse_results_artifact
        ON artifact_parse_results (job_artifact_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_artifact_parse_results_parser
        ON artifact_parse_results (parser_name)
    """,
    # Deleted-pipeline browse: filter by parser then join artifacts by id.
    """
    CREATE INDEX IF NOT EXISTS ix_artifact_parse_results_parser_artifact
        ON artifact_parse_results (parser_name, job_artifact_id)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_artifact_parse_results_artifact_created
        ON artifact_parse_results (job_artifact_id, created_at DESC)
    """,
    # Parser browse + size join used by deleted social / carve fallbacks.
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_size_id
        ON job_artifacts (job_id, size_bytes DESC NULLS LAST, id)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_ext_id
        ON job_artifacts (job_id, lower(coalesce(extension,'')), id)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_ocr_status_id
        ON job_artifacts (job_id, ocr_status, id)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_quality_unchecked
        ON job_artifacts (job_id, id)
        WHERE coalesce(metadata->>'ocr_quality_checked','false') <> 'true'
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_company_leakage
        ON job_artifacts (job_id, id)
        WHERE coalesce(metadata->>'company_leakage_candidate','false') = 'true'
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_job_evidence_browse_cache_job
        ON job_evidence_browse_cache (job_id, cache_kind)
    """,
)

_CACHE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS job_evidence_browse_cache (
    job_id UUID NOT NULL,
    cache_kind TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (job_id, cache_kind)
)
"""

_TRGM_INDEX_SQL = (
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_path_trgm
        ON job_artifacts USING gin (file_path gin_trgm_ops)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_name_trgm
        ON job_artifacts USING gin (file_name gin_trgm_ops)
    """,
    # Family Open uses lower(replace(file_path,'\\','/')) LIKE '%...%'.
    # The raw-path index above does not match that expression.
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_norm_path_trgm
        ON job_artifacts USING gin (lower(replace(file_path, '\\', '/')) gin_trgm_ops)
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_job_artifacts_name_lower_trgm
        ON job_artifacts USING gin (lower(file_name) gin_trgm_ops)
    """,
)


def _family_page_index_sql() -> list[str]:
    """Path-ordered indexes whose predicate is exactly one inventory family.

    A plain (job_id, file_path) scan reads non-matching files until the page
    fills. Pictures discarded thousands of rows to return 20. These indexes
    contain only the family, already ordered by path.
    """
    from app.services.artifact_family_browse import (
        _AUDIO_SQL,
        _DOC_SQL,
        _IMAGE_SQL,
        _TRASH_SQL,
        _VIDEO_SQL,
        _WA_EXCLUDE_SQL,
        _WA_MEDIA_SQL,
    )

    live = f"NOT {_TRASH_SQL}"
    specs = (
        ("ix_ja_pictures_path", f"{_IMAGE_SQL} AND {live}"),
        ("ix_ja_videos_path", f"{_VIDEO_SQL} AND {live}"),
        ("ix_ja_audio_path", f"{_AUDIO_SQL} AND {live}"),
        ("ix_ja_documents_path", f"{_DOC_SQL} AND {live}"),
        ("ix_ja_wa_media_path", f"{_WA_MEDIA_SQL} AND {_WA_EXCLUDE_SQL} AND {live}"),
        ("ix_ja_wa_images_path", f"{_WA_MEDIA_SQL} AND {_IMAGE_SQL} AND {_WA_EXCLUDE_SQL} AND {live}"),
        ("ix_ja_wa_videos_path", f"{_WA_MEDIA_SQL} AND {_VIDEO_SQL} AND {_WA_EXCLUDE_SQL} AND {live}"),
        ("ix_ja_wa_audio_path", f"{_WA_MEDIA_SQL} AND {_AUDIO_SQL} AND {_WA_EXCLUDE_SQL} AND {live}"),
        ("ix_ja_wa_docs_path", f"{_WA_MEDIA_SQL} AND {_DOC_SQL} AND {_WA_EXCLUDE_SQL} AND {live}"),
    )
    return [
        f"CREATE INDEX IF NOT EXISTS {name} ON job_artifacts (job_id, file_path) WHERE {predicate}"
        for name, predicate in specs
    ]


_PRIORITY_PAGE_INDEXES = (
    """
    CREATE INDEX IF NOT EXISTS ix_mna_pictures_page
        ON mobile_normalized_artifacts (job_id, timestamp_utc DESC NULLS LAST, artifact_id)
        WHERE artifact_type='photo'
           OR (artifact_type='media_reference' AND data->>'mime' LIKE 'image/%')
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_mna_videos_page
        ON mobile_normalized_artifacts (job_id, timestamp_utc DESC NULLS LAST, artifact_id)
        WHERE artifact_type='video'
           OR (artifact_type='media_reference' AND data->>'mime' LIKE 'video/%')
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_mna_audio_page
        ON mobile_normalized_artifacts (job_id, timestamp_utc DESC NULLS LAST, artifact_id)
        WHERE artifact_type='audio'
           OR (artifact_type='media_reference' AND data->>'mime' LIKE 'audio/%')
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_mna_documents_page
        ON mobile_normalized_artifacts (job_id, timestamp_utc DESC NULLS LAST, artifact_id)
        WHERE artifact_type='document'
    """,
)


def ensure_evidence_browse_indexes(db: Session) -> None:
    """Idempotent DDL for evidence-list SQL. No-op after the first success per Session."""
    key = id(db)
    if key in _READY:
        return
    try:
        execute(db, _CACHE_TABLE_SQL)
    except Exception as exc:
        log.debug("evidence cache table skipped: %s", exc)
        try:
            db.rollback()
        except Exception:
            pass
    for sql in (*_BROWSE_INDEX_SQL, *_family_page_index_sql(), *_PRIORITY_PAGE_INDEXES):
        nested = None
        try:
            nested = db.begin_nested()
            execute(db, sql)
            nested.commit()
        except Exception as exc:
            log.warning("browse index skipped: %s", exc)
            try:
                if nested is not None:
                    nested.rollback()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
    try:
        execute(db, "CREATE EXTENSION IF NOT EXISTS pg_trgm")
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    else:
        for sql in _TRGM_INDEX_SQL:
            try:
                execute(db, sql)
            except Exception as exc:
                log.debug("trgm index skipped: %s", exc)
                try:
                    db.rollback()
                except Exception:
                    pass
    try:
        db.flush()
    except Exception:
        pass
    _READY.add(key)


def ensure_v68_hot_indexes(db):
    for sql in [
      "CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_parse_status_id ON job_artifacts(job_id,parse_status,id)",
      "CREATE INDEX IF NOT EXISTS ix_job_artifacts_job_stage_status_id ON job_artifacts(job_id,stage_status,id)",
      "CREATE INDEX IF NOT EXISTS ix_job_artifacts_rag_ready ON job_artifacts(job_id,id) WHERE parse_status='done'",
      "CREATE INDEX IF NOT EXISTS ix_job_artifacts_ocr_bucket_pending ON job_artifacts(job_id,id) WHERE ocr_status='pending' AND coalesce(metadata->>'ocr_quality_bucket','false')='true'",
      "CREATE INDEX IF NOT EXISTS ix_job_artifacts_rag_stable_pending ON job_artifacts(job_id,id) WHERE parse_status='done' AND coalesce(stage_status,'') <> 'rag_done'",
      "CREATE INDEX IF NOT EXISTS ix_job_artifacts_rag_unchunked ON job_artifacts(job_id,id) WHERE coalesce(metadata->>'serial_chunked','false')<>'true'",
      "CREATE INDEX IF NOT EXISTS ix_ocr_results_artifact_page_created ON ocr_results(job_artifact_id,page_index,created_at DESC)",
      "CREATE INDEX IF NOT EXISTS ix_rag_chunks_job_path_type_idx ON rag_chunks(job_id,file_path,chunk_type,id)",
    ]:
        execute(db,sql)
    db.commit()

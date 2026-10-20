# Inventory restarting during signature carving — targeted fix

Root cause in supplied archive: `progress_agent.classify_stage` cancels a running stage after 90 seconds without committed **catalog items**. Signature carving can legitimately take >10 minutes before it commits any catalog count. Logs show a repeat path-index scan after the earlier carve was canceled.

This patch gives a **live** inventory-prewarm operation up to 1800 seconds of grace (configurable by `FORENSIC_INVENTORY_PREWARM_GRACE_SECONDS`, constrained to 600–3600 seconds), as long as its heartbeat is fresh. It does not mark any work complete, disable stuck-worker recovery, or relax parse/OCR stages. After grace expires, the existing cancellation/recovery logic applies. This addresses the demonstrated restart loop, not all other runtime performance issues.

## Install
Replace `backend/app/services/progress_agent.py` and redeploy the process-agent / progress worker image, taking care not to restart a currently active evidence extraction. Back up first. Run `python tests/test_inventory_preparation_liveness.py`.

## Important
- The requested one-hour **whole-case** SLA cannot be guaranteed based only on this code: time depends on bytes read, filesystem defects, MinIO speed, disk/media throughput, decoder costs, graph writes and hardware.
- Never use an elapsed-time threshold to set 100% unless every item is terminal or explicitly excluded with an auditable coverage limitation. Otherwise the case is incomplete.
- Existing carving can still consume substantial time; profile `_scan_unallocated` and catalog counters, cache completed results, and consider optional *explicit* post-processing sidecars only after coverage requirements are agreed.
- Production integration and load tests were not available; run database/worker integration and a >30-minute carving workload before declaring production-ready.

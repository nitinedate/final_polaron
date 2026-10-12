import { CheckCircle2, Circle, Loader2, XCircle } from "lucide-react";
import type { PipelineProgress } from "../../lib/types/forensic";

type SerialPipeline = NonNullable<PipelineProgress["serial_pipeline"]>;

export function SerialPipelineBanner({ pipeline, paused, compact, elapsed }: {
  pipeline: SerialPipeline; paused: boolean; compact: boolean; elapsed?: string | null;
}) {
  const active = pipeline.stages.find((stage) => stage.id === pipeline.current_stage);
  const timeTaken = (stage: SerialPipeline["stages"][number]) => {
    if (!stage.started_at) return null;
    const begin = Date.parse(stage.started_at);
    const end = stage.completed_at ? Date.parse(stage.completed_at) : Date.now();
    if (!Number.isFinite(begin) || !Number.isFinite(end) || end < begin) return null;
    const seconds = Math.floor((end - begin) / 1000);
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m ${seconds % 60}s`;
  };
  const skipReason = (stage: SerialPipeline["stages"][number]) => String(stage.details?.skip_reason || "");
  const skipIsException = (stage: SerialPipeline["stages"][number]) => {
    const reason = skipReason(stage);
    return stage.skipped > 0 && reason.length > 0 && !/forensic-only|low-value|non-forensic|media|oversized|pre-filtered|no parsed|no text|unsupported|recorded evidence exceptions|explicit extractor/i.test(reason);
  };
  const exceptions = pipeline.stages.filter((stage) => stage.failed > 0 || stage.status === "failed"
    || Boolean(stage.error) || Number(stage.details?.errors || 0) > 0 || stage.details?.coverage_complete === false
    || skipIsException(stage));
  const exceptionText = (stage: SerialPipeline["stages"][number]) => stage.error
    || (stage.failed > 0 ? `${stage.failed.toLocaleString()} failed work units`
      : skipIsException(stage) ? `${stage.skipped.toLocaleString()} skipped · ${skipReason(stage)}`
        : "Coverage exceptions recorded; review evidence counters.");
  const stateLabel = (status: string) => status === "done" ? "Completed" : status === "skipped" ? "Skipped"
    : status === "running" && !paused ? "Running" : status === "failed" ? "Failed"
      : paused && status === "running" ? "Paused" : "Waiting";
  return <div className={`rounded-xl border border-slate-200 bg-white p-4 ${compact ? "" : "mb-4"}`}>
    <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
      <p className="text-sm font-semibold text-ink-900">Forensic processing</p>
      <span className="text-xs tabular-nums text-ink-600">{pipeline.overall_pct}%{elapsed ? ` · ${elapsed}` : ""}</span>
    </div>
    <div className="mb-3 h-2 overflow-hidden rounded-full bg-slate-200">
      <div className={`h-2 transition-all ${pipeline.complete ? "bg-emerald-500" : "bg-amber-400"}`} style={{ width: `${pipeline.overall_pct}%` }} />
    </div>
    <p className="mb-3 text-xs text-ink-700">{pipeline.complete ? "Processing completed — review evidence coverage" : paused ? "Processing paused"
      : pipeline.upgrade_required ? "Reprocess this case to apply the updated evidence stages"
      : active ? `${paused ? "Paused" : active.process_status || stateLabel(active.status)}: ${active.label}` : "Waiting for the next stage"}</p>
    <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
      {pipeline.stages.map((stage, index) => <li key={stage.id}
        className={`min-w-0 rounded-lg border p-3 text-xs ${stage.status === "running" ? "border-amber-200 bg-amber-50"
          : stage.status === "failed" ? "border-red-200 bg-red-50"
            : stage.status === "done" || stage.status === "skipped" ? "border-emerald-100 bg-emerald-50" : "border-slate-200"}`}>
        <div className="flex items-start gap-2">
          {stage.status === "done" || stage.status === "skipped" ? <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-600" />
            : stage.status === "failed" ? <XCircle className="h-4 w-4 shrink-0 text-red-600" />
              : stage.status === "running" && !paused ? <Loader2 className="h-4 w-4 shrink-0 animate-spin text-amber-600" /> : <Circle className="h-4 w-4 shrink-0 text-slate-400" />}
          <span className="min-w-0 flex-1 break-words font-semibold text-ink-900">{index + 1}. {stage.label}</span>
          <span className="shrink-0 font-bold tabular-nums">{stage.pct}%</span>
        </div>
        <div className="mt-2 flex flex-wrap justify-between gap-2 text-ink-600">
          <span>{paused && stage.status === "running" ? "Paused" : stage.process_status || stateLabel(stage.status)}</span>
          {stage.total > 0 && <span className="tabular-nums">{Math.min(stage.total, stage.completed + stage.failed + stage.skipped).toLocaleString()} / {stage.total.toLocaleString()} items</span>}
        </div>
        {timeTaken(stage) && <p className="mt-1 text-[11px] tabular-nums text-ink-600">{stage.status === "running" ? "Elapsed" : "Time taken"}: {timeTaken(stage)}</p>}
        {stage.status !== "done" && stage.status !== "skipped" && typeof stage.details?.progress_agent_reconciliation === "object" && stage.details?.progress_agent_reconciliation ? (
          <p className="mt-2 rounded-md bg-white/70 px-2 py-1.5 text-[11px] leading-snug text-amber-900">
            {String((stage.details.progress_agent_reconciliation as Record<string, unknown>).summary || "progressAgent is verifying remaining work")}
          </p>
        ) : null}
      </li>)}
    </ul>
    <div className="mt-3 rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-950">
      <p className="font-semibold">Source limitations · {pipeline.source_coverage?.status || "unknown"} coverage</p>
      <p className="mt-1">{pipeline.source_coverage?.notice || "Processing 100% means scheduled work has finished. It does not mean full device or evidence coverage."}</p>
      <p className="mt-1">{pipeline.source_coverage?.scope_note || "Missing keys, unavailable private app data and inaccessible or overwritten evidence may limit this acquisition."}</p>
      <details className="mt-2" >
        <summary className="cursor-pointer font-semibold">Review {pipeline.source_coverage?.limitations?.length || 0} detailed coverage limitations and remediation actions</summary>
      {pipeline.source_coverage?.limitations?.map((item, index) => <div key={`${item.code}:${item.source}:${index}`} className="mt-2 border-t border-amber-200 pt-2">
        <p className="font-semibold">{item.source}{item.count !== undefined ? ` · ${item.count.toLocaleString()} items` : ""}</p>
        <p>{item.reason}</p><p className="mt-1">Follow-up: {item.action}</p>
      </div>)}
      </details>
    </div>
    {active?.error && <p className="mt-3 rounded bg-amber-50 p-2 text-xs text-amber-900">{active.error}</p>}
    {exceptions.length > 0 && <div className="mt-3 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-900">
      <p className="mb-1 font-semibold">Processing exceptions</p>
      {exceptions.map((stage) => <p key={stage.id}>{stage.label}: {exceptionText(stage)}</p>)}
    </div>}
  </div>;
}

import { useEffect, useRef, useState } from "react";
import { api, type Claim, type Dismissal, type EventContext, type Signal } from "../api/client";
import { STAGE, fmtDateTime } from "../lib/format";

export type DrawerTarget = { kind: "claim"; claim: Claim; signals: Signal[]; stage?: string } | { kind: "dismissal"; d: Dismissal };

function RuleCard({ s }: { s: Signal }) {
  const m = s.rule_meta;
  const tags = m.tags ?? [];
  const fps = m.falsepositives ?? [];
  const req = s.requires ?? [];
  const prod = s.produces ?? [];
  const args = (a?: Record<string, string>) => Object.entries(a ?? {}).filter(([k]) => k !== "session").map(([, v]) => v).join(", ");
  return (
    <div className="rounded-[4px] border border-rule bg-paper p-3">
      <p className="flex flex-wrap items-baseline gap-x-2">
        <span className="font-mono text-[12px] text-slate">{s.detector}</span>
        <span className="font-[650]">{s.title}</span>
        <span className={`ml-auto text-[12px] ${m.level === "critical" || m.level === "high" ? "text-breach" : "text-slate"}`}>
          {m.level} severity rule
        </span>
      </p>
      {tags.length > 0 && (
        <p className="mt-1 font-mono text-[11.5px] text-slate" translate="no">
          {tags.join("  ")}
        </p>
      )}
      {fps.length > 0 && (
        <p className="mt-2 text-[13px] text-graphite">
          <span className="text-slate">Could also be: </span>
          {fps.join("; ")}.
        </p>
      )}
      {req.length > 0 && (
        <p className="mt-1 text-[13px] text-graphite">
          <span className="text-slate">Only counts if this already held: </span>
          {req.map((r) => `${r.name}(${args(r.args)})`).join(" or ")}
        </p>
      )}
      {prod.length > 0 && (
        <p className="mt-1 text-[13px] text-graphite">
          <span className="text-slate">Establishes: </span>
          {prod.map((r) => `${r.name}(${args(r.args)})`).join(", ")}
        </p>
      )}
    </div>
  );
}

function EvidenceLine({ caseId, eventId, role }: { caseId: string; eventId: string; role: string }) {
  const [ctx, setCtx] = useState<EventContext | null>(null);
  const [err, setErr] = useState(false);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    let live = true;
    api.event(caseId, eventId, 3).then((c) => live && setCtx(c), () => live && setErr(true));
    return () => {
      live = false;
    };
  }, [caseId, eventId]);
  if (err) return <li className="text-[13px] text-breach">Could not load {eventId}.</li>;
  if (!ctx) return <li className="h-10 animate-pulse rounded bg-rule-soft" aria-hidden="true" />;
  const e = ctx.event;
  return (
    <li className="rounded-[4px] border border-rule bg-sheet">
      <div className="flex flex-wrap items-baseline gap-x-3 border-b border-rule-soft px-3 py-1.5 text-[12px] text-slate">
        <span className="font-mono text-graphite" translate="no">
          {ctx.file_name}:{ctx.line_no}
        </span>
        <span>{fmtDateTime(e.ts_utc)}</span>
        {role === "contradicts" && <span className="text-cleared">evidence against</span>}
        {role === "context" && <span>context</span>}
        <button type="button" onClick={() => setOpen((o) => !o)} aria-expanded={open} className="ml-auto underline underline-offset-2 hover:text-graphite">
          {open ? "Hide surrounding lines" : "Show surrounding lines"}
        </button>
      </div>
      <pre className="px-3 py-2 font-mono text-[12px] leading-[1.6] break-all whitespace-pre-wrap" translate="no">
        {open &&
          ctx.before.map((l, i) => (
            <div key={`b${i}`} className="text-mist">
              {l}
            </div>
          ))}
        <div className={`-mx-3 border-l-2 px-3 text-graphite ${role === "supports" ? "border-breach bg-breach-soft" : role === "contradicts" ? "border-cleared bg-cleared-soft" : "border-mist bg-paper"}`}>
          {e.raw_text}
        </div>
        {open &&
          ctx.after.map((l, i) => (
            <div key={`a${i}`} className="text-mist">
              {l}
            </div>
          ))}
      </pre>
      <p className="px-3 pb-2 text-[12px] text-slate">
        Read as: <span className="text-graphite">{e.action}</span>, {e.outcome}
        {e.user ? `, user ${e.user}` : ""}
        {e.src_ip ? `, from ${e.src_ip}` : ""}
        {e.dst_ip ? `, to ${e.dst_ip}` : ""}
        {e.host ? `, on ${e.host}` : ""}
        {e.parse_flags?.length ? `. Assumptions: ${e.parse_flags.join(", ").replace(/_/g, " ")}` : ""}
      </p>
    </li>
  );
}

export default function EvidenceDrawer({ caseId, target, onClose }: { caseId: string; target: DrawerTarget | null; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const prevFocus = useRef<HTMLElement | null>(null);
  useEffect(() => {
    if (!target) return;
    prevFocus.current = document.activeElement as HTMLElement;
    ref.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      prevFocus.current?.focus?.();
    };
  }, [target, onClose]);
  if (!target) return null;

  const evidence = (target.kind === "claim" ? target.claim.evidence : target.d.counter_evidence) ?? [];
  const title = target.kind === "claim" ? target.claim.text : target.d.reasons[0];

  return (
    <div className="fixed inset-0 z-40" role="presentation">
      <button type="button" aria-label="Close evidence" onClick={onClose} className="absolute inset-0 bg-graphite/20" tabIndex={-1} />
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby="drawer-title"
        tabIndex={-1}
        className="scroll-quiet absolute top-0 right-0 flex h-full w-full max-w-[640px] flex-col overflow-y-auto border-l border-rule bg-paper shadow-[-12px_0_32px_rgba(28,33,40,0.12)]"
      >
        <header className="sticky top-0 z-10 border-b border-rule bg-paper px-6 pt-5 pb-4">
          <div className="flex items-start gap-4">
            <p className="text-[13px] text-slate">
              {target.kind === "claim"
                ? target.stage
                  ? `${STAGE[target.stage as keyof typeof STAGE]?.plain ?? target.stage}: the evidence`
                  : "The evidence"
                : target.d.decision === "watchlist"
                  ? "Why this is only on the watchlist"
                  : "Why this was cleared"}
            </p>
            <button type="button" onClick={onClose} className="ml-auto rounded-[4px] px-2 py-1 text-[13px] text-slate hover:bg-rule-soft hover:text-graphite">
              Close <span aria-hidden="true">(Esc)</span>
            </button>
          </div>
          <h2 id="drawer-title" className="pretty mt-1 text-[18px] leading-[1.35] font-[600]">
            {title}
          </h2>
        </header>

        <div className="space-y-5 px-6 py-5">
          {target.kind === "claim" && target.signals.length > 0 && (
            <section aria-label="Rules that fired" className="space-y-2">
              {target.signals.map((s) => (
                <RuleCard key={s.id} s={s} />
              ))}
            </section>
          )}
          {target.kind === "dismissal" && (
            <section aria-label="Reasons" className="space-y-2 text-[14px]">
              <ul className="list-disc space-y-1 pl-5">
                {target.d.reasons.slice(1).map((r) => (
                  <li key={r}>{/^[a-z]+[ ,]/.test(r) ? r[0].toUpperCase() + r.slice(1) : r}.</li>
                ))}
              </ul>
              {target.d.would_flag_if && (
                <p className="rounded-[4px] border border-rule bg-sheet p-3">
                  <span className="text-slate">It would be flagged if there were </span>
                  {target.d.would_flag_if}.
                </p>
              )}
            </section>
          )}
          <section aria-labelledby="ev-h">
            <h3 id="ev-h" className="w-semi text-[15px] font-[650]">
              Source lines <span className="nums font-[450] text-slate">{evidence.length}</span>
            </h3>
            <ul className="mt-2 space-y-2">
              {evidence.map((r) => (
                <EvidenceLine key={r.event_id} caseId={caseId} eventId={r.event_id} role={r.role} />
              ))}
            </ul>
          </section>
        </div>
      </div>
    </div>
  );
}

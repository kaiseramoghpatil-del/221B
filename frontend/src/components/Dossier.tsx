import type { AttackStep, Claim, Dismissal, IncidentDetail } from "../api/client";
import { STAGE, entityLabel, fmtTime, fmtPct } from "../lib/format";

/** Highlights attacker entities inside plain sentences. */
function Prose({ text, attacker }: { text: string; attacker: string[] }) {
  if (!attacker.length) return <>{text}</>;
  const esc = attacker.map((a) => a.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).sort((a, b) => b.length - a.length);
  const parts = text.split(new RegExp(`(${esc.join("|")})`, "g"));
  return (
    <>
      {parts.map((p, i) =>
        attacker.includes(p) ? (
          <span key={i} className="font-[600] text-breach">
            {p}
          </span>
        ) : (
          <span key={i}>{p}</span>
        ),
      )}
    </>
  );
}

type FindingsProps = {
  detail: IncidentDetail;
  attacker: string[];
  focusStep: string | null;
  onFocus: (id: string | null) => void;
  onOpenClaim: (c: Claim) => void;
  activeClaim?: string;
};

export function Findings({ detail, attacker, focusStep, onFocus, onOpenClaim, activeClaim }: FindingsProps) {
  const steps = new Map<string, AttackStep>((detail.incident.steps ?? []).map((s) => [s.id, s]));
  const stepClaims = detail.claims.filter((c) => c.step_id && steps.has(c.step_id));
  const other = detail.claims.filter((c) => !c.step_id);
  return (
    <section aria-labelledby="findings-h">
      <h2 id="findings-h" className="w-semi text-[19px] font-[650]">
        What happened, step by step
      </h2>
      <p className="mt-1 text-[13.5px] text-slate">Each step is a finding. Open it to see the exact log lines and the rule that fired.</p>
      <ol className="mt-4 space-y-1">
        {stepClaims.map((c) => {
          const st = steps.get(c.step_id!)!;
          const active = focusStep === st.id || activeClaim === c.id;
          return (
            <li key={c.id}>
              <button
                type="button"
                onClick={() => onOpenClaim(c)}
                onMouseEnter={() => onFocus(st.id)}
                onMouseLeave={() => onFocus(null)}
                onFocus={() => onFocus(st.id)}
                onBlur={() => onFocus(null)}
                aria-label={`Step ${st.order}, ${STAGE[st.stage].plain}. ${c.text}. Open ${c.evidence.length} cited log lines.`}
                className={`grid w-full grid-cols-[28px_1fr] gap-x-2 rounded-[4px] px-2 py-2.5 text-left transition-colors ${
                  active ? "bg-breach-soft" : "hover:bg-rule-soft"
                }`}
              >
                <span className="w-cond nums pt-0.5 text-[18px] leading-none font-[700] text-breach">{st.order}</span>
                <span className="min-w-0">
                  <span className="flex flex-wrap items-baseline gap-x-2">
                    <span className="font-[650]">{STAGE[st.stage].plain}</span>
                    <span className="text-[12px] text-mist">{STAGE[st.stage].tactic}</span>
                    <span className="nums ml-auto text-[12.5px] text-slate">{fmtTime(st.t_start)}</span>
                  </span>
                  <span className="pretty mt-0.5 block text-[14px] leading-[1.45] break-words text-graphite">
                    <Prose text={c.text} attacker={attacker} />
                  </span>
                  <span className="mt-1 flex items-center gap-3 text-[12.5px] text-slate">
                    <span className="underline decoration-rule underline-offset-2">
                      {st.summary_count && st.summary_count > c.evidence.length
                        ? `${c.evidence.length} of ${st.summary_count} log lines`
                        : `${c.evidence.length} log line${c.evidence.length === 1 ? "" : "s"}`}
                    </span>
                    {st.inferred && <span className="text-watch">continuity inferred</span>}
                  </span>
                </span>
              </button>
            </li>
          );
        })}
      </ol>

      {other.length > 0 && (
        <div className="mt-6">
          <h3 className="w-semi text-[16px] font-[650]">Gaps and caveats</h3>
          <ul className="mt-2 space-y-2">
            {other.map((c) => (
              <li key={c.id}>
                <button
                  type="button"
                  onClick={() => onOpenClaim(c)}
                  className="w-full rounded-[4px] border-l-2 py-1 pr-2 pl-3 text-left text-[13.5px] leading-[1.45] hover:bg-rule-soft"
                  style={{ borderColor: c.type === "GAP" ? "var(--color-watch)" : "var(--color-rule)" }}
                >
                  <span className={c.type === "GAP" ? "font-[600] text-watch" : "font-[600] text-slate"}>
                    {c.type === "GAP" ? "Missing from the logs. " : "Note. "}
                  </span>
                  {c.text}
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

/** Sentence-case a reason, but never touch identifiers such as host names or IPs at the start. */
const cap = (x: string) => (/^[a-z]+[ ,]/.test(x) ? x[0].toUpperCase() + x.slice(1) : x);

export function NotFlagged({ dismissals, onOpen }: { dismissals: Dismissal[]; onOpen: (d: Dismissal) => void }) {
  if (!dismissals.length) return null;
  return (
    <section aria-labelledby="nf-h" className="mt-8">
      <h2 id="nf-h" className="w-semi text-[19px] font-[650]">
        Exhibit C. Looked suspicious, but isn’t the intruder
      </h2>
      <p className="text-[13.5px] text-slate">Loud is not the same as dangerous. Each one is explained, with the log lines that clear it.</p>
      <ul className="mt-3 grid gap-3 md:grid-cols-2">
        {dismissals.map((d) => {
          const tone = d.decision === "watchlist" ? "text-watch" : "text-cleared";
          return (
            <li key={d.id}>
              <button
                type="button"
                onClick={() => onOpen(d)}
                className="h-full w-full rounded-[4px] border border-rule bg-sheet p-4 text-left transition-colors hover:border-graphite"
              >
                <span className="flex items-baseline gap-2">
                  <span className={`font-mono text-[13px] font-[600] ${tone}`} translate="no">
                    {entityLabel(d.entity)}
                  </span>
                  <span className={`text-[12.5px] ${tone}`}>{d.decision === "watchlist" ? "kept on the watchlist" : "cleared"}</span>
                </span>
                <span className="pretty mt-1.5 block text-[14px] leading-[1.45] font-[550] text-graphite">{cap(d.reasons[0])}</span>
                <ul className="mt-1.5 space-y-0.5 text-[13px] leading-[1.45] text-slate">
                  {d.reasons.slice(1).map((r) => (
                    <li key={r}>{cap(r)}.</li>
                  ))}
                </ul>
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

export function ScoreNote({ detail, labelOf }: { detail: IncidentDetail; labelOf: (signalId: string) => string }) {
  const b = detail.score_breakdown;
  const top = b.items.slice(0, 6);
  const max = Math.max(...top.map((i) => i.contribution), 0.01);
  const parts = b.confidence_parts as Record<string, number>;
  return (
    <details className="group mt-8">
      <summary className="w-semi cursor-pointer text-[16px] font-[650] marker:text-mist">How the score was built</summary>
      <p className="mt-2 text-[13.5px] text-slate">
        A signal counts fully only when something that happened later depends on it. Isolated alarms count for a fifth.
      </p>
      <ul className="mt-3 space-y-1.5">
        {top.map((i) => (
          <li key={i.signal_id} className="grid grid-cols-[1fr_120px_40px] items-center gap-2 text-[13px]">
            <span className="truncate">{labelOf(i.signal_id)}</span>
            <span className="h-2 rounded-sm bg-rule-soft">
              <span className="block h-2 rounded-sm bg-breach" style={{ width: `${(i.contribution / max) * 100}%` }} />
            </span>
            <span className="nums text-right text-slate">×{i.consequence_factor}</span>
          </li>
        ))}
      </ul>
      <p className="nums mt-3 text-[13px] text-slate">
        Confidence {fmtPct(b.confidence)}: {fmtPct(parts.links_backed_by_predicates ?? 0)} of links backed by a logged prerequisite,
        detector confidence {fmtPct(parts.mean_detector_confidence ?? 0)}, {parts.logging_gaps ?? 0} logging gap(s).
      </p>
    </details>
  );
}

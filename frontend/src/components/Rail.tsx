import type { Incident, Suspect } from "../api/client";
import { ROLE, entityKind, entityLabel, fmtPct } from "../lib/format";

function Spark({ points, tone }: { points: [string, number][]; tone: string }) {
  if (points.length < 2) return <svg width={64} height={18} aria-hidden="true" />;
  const xs = points.map(([t]) => new Date(t).getTime());
  const ys = points.map(([, v]) => v);
  const [x0, x1] = [Math.min(...xs), Math.max(...xs)];
  const y1 = Math.max(...ys, 0.01);
  const d = points.map(([, v], i) => `${i ? "L" : "M"}${((xs[i] - x0) / Math.max(1, x1 - x0)) * 62 + 1},${17 - (v / y1) * 15}`).join(" ");
  return (
    <svg width={64} height={18} aria-hidden="true">
      <path d={d} fill="none" stroke={tone} strokeWidth={1.5} />
    </svg>
  );
}

const roleTone = (role: string) =>
  role === "attacker_infra" || role === "compromised_account"
    ? "var(--color-breach)"
    : role === "noisy_benign"
      ? "var(--color-watch)"
      : "var(--color-slate)";

type Props = {
  incidents: Incident[];
  selected?: string;
  onSelect: (id: string) => void;
  suspects: Suspect[];
};

export default function Rail({ incidents, selected, onSelect, suspects }: Props) {
  const infra = suspects.filter((s) => s.role === "attacker_infra").sort((a, b) => b.distinct_stages - a.distinct_stages);
  const folded = new Set(infra.slice(2).map((s) => s.entity.id));
  const head = suspects.filter((s) => !folded.has(s.entity.id));
  const inc = incidents.filter((i) => i.status === "incident");
  const watch = incidents.filter((i) => i.status === "watchlist");
  return (
    <nav aria-label="Incidents, watchlist and suspects" className="space-y-7">
      <section aria-labelledby="rail-inc">
        <h2 id="rail-inc" className="w-semi text-[15px] font-[650]">
          Incidents <span className="nums font-[450] text-slate">{inc.length}</span>
        </h2>
        {inc.length === 0 && <p className="mt-2 text-[13.5px] text-slate">No multi-stage intrusion found. Check the watchlist.</p>}
        <ul className="mt-2 space-y-1">
          {inc.map((i) => (
            <li key={i.id}>
              <button
                type="button"
                aria-current={selected === i.id ? "true" : undefined}
                onClick={() => onSelect(i.id)}
                className={`w-full rounded-[4px] border-l-2 px-3 py-2 text-left transition-colors ${
                  selected === i.id ? "border-breach bg-sheet" : "border-transparent hover:bg-rule-soft"
                }`}
              >
                <span className="block text-[13.5px] leading-[1.35] font-[600]">{i.title}</span>
                <span className="nums mt-1 block text-[12.5px] text-slate">
                  {(i.stages_covered ?? []).length} stages, {i.signal_ids.length} signals, confidence {fmtPct(i.confidence)}
                </span>
              </button>
            </li>
          ))}
        </ul>
      </section>

      {watch.length > 0 && (
        <section aria-labelledby="rail-watch">
          <h2 id="rail-watch" className="w-semi text-[15px] font-[650]">
            Watchlist <span className="nums font-[450] text-slate">{watch.length}</span>
          </h2>
          <p className="mt-1 text-[12.5px] text-slate">Single-stage findings. Nothing correlated follows them.</p>
          <ul className="mt-2 space-y-1">
            {watch.map((i) => (
              <li key={i.id}>
                <button
                  type="button"
                  aria-current={selected === i.id ? "true" : undefined}
                  onClick={() => onSelect(i.id)}
                  className={`w-full rounded-[4px] border-l-2 px-3 py-1.5 text-left transition-colors ${
                    selected === i.id ? "border-watch bg-sheet" : "border-transparent hover:bg-rule-soft"
                  }`}
                >
                  <span className="block text-[13px] leading-[1.35]">
                    {i.watchlist_priority === "high" && <span className="font-[650] text-watch">High priority. </span>}
                    {i.title}
                  </span>
                  <span className="block truncate font-mono text-[11.5px] text-slate">
                    {i.entities.filter((e) => entityKind(e) !== "host").map(entityLabel).slice(0, 2).join(", ")}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section aria-labelledby="rail-sus">
        {/* rotating attacker infrastructure: show the two most involved addresses, fold the rest */}
        <h2 id="rail-sus" className="w-semi text-[15px] font-[650]">
          Who and what is involved
        </h2>
        <ul className="mt-2 divide-y divide-rule-soft">
          {head.map((s) => (
            <li key={s.entity.id} className="grid grid-cols-[1fr_auto] items-center gap-x-2 py-2">
              <span className="min-w-0">
                <span
                  className={`block truncate text-[13.5px] font-[600] ${entityKind(s.entity.id) === "ip" ? "font-mono text-[12.5px]" : ""}`}
                  style={{ color: roleTone(s.role) === "var(--color-slate)" ? "var(--color-graphite)" : roleTone(s.role) }}
                  translate="no"
                >
                  {entityLabel(s.entity.id)}
                </span>
                <span className="block text-[12px] text-slate">
                  {ROLE[s.role] ?? s.role}
                  {s.distinct_stages > 0 ? `, ${s.distinct_stages} stage${s.distinct_stages > 1 ? "s" : ""}` : ""}
                </span>
              </span>
              <Spark points={s.risk_ledger as [string, number][]} tone={roleTone(s.role)} />
            </li>
          ))}
        </ul>
        {folded.size > 0 && (
          <details className="mt-1 text-[13px]">
            <summary className="cursor-pointer py-1 text-slate hover:text-graphite">{folded.size} more attacker addresses (rotation)</summary>
            <ul className="mt-1 columns-2 font-mono text-[12px] text-breach" translate="no">
              {[...folded].map((id) => (
                <li key={id}>{entityLabel(id)}</li>
              ))}
            </ul>
          </details>
        )}
      </section>
    </nav>
  );
}

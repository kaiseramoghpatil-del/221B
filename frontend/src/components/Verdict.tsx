import type { CaseSummary, Claim, IncidentDetail, Suspect } from "../api/client";
import { entityLabel, fmtBytes, fmtDateTime, fmtDuration, fmtNum, fmtPct } from "../lib/format";

const B = ({ children }: { children: React.ReactNode }) => <span className="whitespace-nowrap text-breach">{children}</span>;
const K = ({ children }: { children: React.ReactNode }) => <span className="whitespace-nowrap">{children}</span>;

function fact(claims: Claim[], type: string, key: string): unknown {
  const c = claims.find((x) => x.type === type);
  return c ? (c.facts as Record<string, unknown>)[key] : undefined;
}

/** The governing finding, in one sentence, then the facts box. */
export function Verdict({ detail, suspects }: { detail: IncidentDetail; suspects: Suspect[] }) {
  const inc = detail.incident;
  const steps = inc.steps ?? [];
  const inIncident = suspects.filter((s) => inc.entities.includes(s.entity.id));
  const account = inIncident.find((s) => s.role === "compromised_account");
  const entryIpFact = fact(detail.claims, "ENTRY", "ip") as string | undefined;
  const entryIpFromStep = entryIpFact ? `ip:${entryIpFact}` : inIncident.find((s) => s.role === "attacker_infra")?.entity.id;
  const victim = inIncident.find((s) => s.role === "victim_host");
  const gb = fact(detail.claims, "EXFIL", "gb") as number | undefined;
  const dst = fact(detail.claims, "EXFIL", "dst") as string | undefined;
  const entry = steps.find((s) => s.stage === "INITIAL_ACCESS");
  const t0 = steps.length ? new Date(steps[0].t_start).getTime() : 0;
  const t1 = steps.length ? Math.max(...steps.map((s) => new Date(s.t_end).getTime())) : 0;
  const hosts = new Set(steps.map((s) => s.target_entity).filter((x): x is string => !!x && x.startsWith("host:")));
  const watch = inc.status === "watchlist";

  return (
    <section aria-labelledby="verdict-h" className="border-b border-rule pb-6">
      {watch && <p className="text-[13px] text-watch">Watchlist item, not an incident</p>}
      <h1 id="verdict-h" className="w-cond balance text-[36px] leading-[1.06] font-[700] tracking-[-0.01em] text-graphite md:text-[42px]">
        {watch ? (
          <>{inc.title}: a single-stage finding with nothing correlated after it.</>
        ) : account && entryIpFromStep ? (
          <>
            <B>{entityLabel(account.entity.id)}</B>’s account was taken over from <B>{entityLabel(entryIpFromStep)}</B>
            {victim ? (
              <>
                {" "}and used to reach <K>{entityLabel(victim.entity.id)}</K>
              </>
            ) : null}
            {gb !== undefined ? (
              <>
                ; <K>{fmtBytes(gb)}</K> left for {dst === entityLabel(entryIpFromStep) ? "the same address" : <B>{dst}</B>}.
              </>
            ) : (
              "."
            )}
          </>
        ) : (
          inc.title
        )}
      </h1>
      <p className="mt-2 text-[15px] text-slate">{inc.title}</p>

      <dl className="mt-5 grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-3 lg:grid-cols-5">
        {[
          ["Got in (UTC)", entry ? fmtDateTime(entry.t_start).replace(" UTC", "") : "not observed"],
          ["Active for", steps.length ? fmtDuration(t1 - t0) : "–"],
          ["Hosts reached", fmtNum(hosts.size)],
          ["Data out", gb !== undefined ? fmtBytes(gb) : "none seen"],
          ["Confidence", fmtPct(inc.confidence)],
        ].map(([k, v]) => (
          <div key={k}>
            <dt className="text-[13px] text-slate">{k}</dt>
            <dd className="w-cond nums text-[22px] leading-tight font-[650]">{v}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

export function Funnel({ summary }: { summary: CaseSummary }) {
  const f = summary.funnel;
  const items: [number, string][] = [
    [f.events, "log events"],
    [f.signals, "detector hits"],
    [f.linked_signals, "linked by evidence"],
    [f.incidents, f.incidents === 1 ? "incident" : "incidents"],
  ];
  return (
    <ol aria-label="From raw events to incidents" className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
      {items.map(([n, label], i) => (
        <li key={label} className="flex items-baseline gap-2">
          {i > 0 && (
            <span aria-hidden="true" className="text-mist">
              ›
            </span>
          )}
          <span className={`w-cond nums text-[20px] font-[700] ${i === items.length - 1 ? "text-breach" : "text-graphite"}`}>{fmtNum(n)}</span>
          <span className="text-[14px] text-slate">{label}</span>
        </li>
      ))}
      {f.watchlist > 0 && (
        <li className="ml-2 text-[14px] text-watch">
          + {f.watchlist} on the watchlist
        </li>
      )}
    </ol>
  );
}

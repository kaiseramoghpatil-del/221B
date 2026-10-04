import { useEffect, useState } from "react";
import { api, ApiError, type S } from "../api/client";
import { fmtNum, fmtPct } from "../lib/format";

type Report = S["EvalReport"];
type Row = Record<string, number>;

const TIER: Record<string, string> = {
  easy: "Easy: fast attacker, one IP, clean logs",
  medium: "Medium: moderate stealth, up to 3 IPs, duplicated and shuffled lines",
  hard: "Hard: slow attacker, 10 to 40 rotating IPs, 10 to 30% of logs lost, clock skew, corrupted lines",
};
const TEMPLATE: Record<string, string> = { T0: "No attack (clean week)", T1: "Stolen credential", T2: "Password guessing", T3: "Insider theft (held-out)" };
const BASELINE = "#6B7583"; // context bars (validated vs crimson: CVD ΔE 12.1, contrast ≥ 3:1)

/** One measure, three readings: horizontal bars, each labelled directly (identity never by colour alone). */
function Bars({ title, unit, rows }: { title: string; unit: (v: number) => string; rows: { label: string; value: number; ours?: boolean }[] }) {
  const max = Math.max(...rows.map((r) => r.value), 1e-9);
  return (
    <figure className="min-w-0">
      <figcaption className="w-semi text-[15px] font-[650]">{title}</figcaption>
      <ul className="mt-3 space-y-2.5">
        {rows.map((r) => (
          <li key={r.label} className="grid grid-cols-[minmax(0,150px)_1fr] items-center gap-3 text-[13.5px]">
            <span className={r.ours ? "font-[650] text-breach" : "text-graphite"}>{r.label}</span>
            <span className="flex items-center gap-2" title={`${r.label}: ${unit(r.value)}`}>
              <svg className="h-3 flex-1" viewBox="0 0 100 12" preserveAspectRatio="none" aria-hidden="true">
                <rect x={0} y={0} width={100} height={12} fill="var(--color-rule-soft)" />
                <rect x={0} y={0} width={Math.max(0.8, (r.value / max) * 100)} height={12} rx={1.2} fill={r.ours ? "var(--color-breach)" : BASELINE} />
              </svg>
              <span className={`nums w-[64px] shrink-0 text-right ${r.ours ? "font-[650]" : ""}`}>{unit(r.value)}</span>
            </span>
          </li>
        ))}
      </ul>
    </figure>
  );
}

export default function Verify({ onOpenCase }: { onOpenCase: (caseId: string) => void }) {
  const [rep, setRep] = useState<Report | null>(null);
  const [held, setHeld] = useState<Report | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [opening, setOpening] = useState<number | null>(null);

  useEffect(() => {
    api.evalHeldout().then(setHeld, () => setHeld(null));
    api.evalLatest().then(setRep, (e) =>
      setErr(e instanceof ApiError && e.status === 404 ? "No benchmark has been run yet. Run: python -m eval.sweep" : "The analysis server is not reachable."),
    );
  }, []);

  async function open(seed: number, params: Record<string, unknown>) {
    setOpening(seed);
    try {
      const { case_id } = await api.createScenario(seed, params);
      onOpenCase(case_id);
    } catch {
      setOpening(null);
    }
  }

  if (err)
    return (
      <main id="main" className="mx-auto max-w-[760px] px-6 py-20">
        <h1 className="w-cond text-[34px] font-[700]">Benchmark not available</h1>
        <p className="mt-3 text-slate">{err}</p>
      </main>
    );
  if (!rep)
    return (
      <main id="main" className="grid min-h-full place-items-center">
        <p aria-live="polite" className="text-slate">
          Loading the benchmark…
        </p>
      </main>
    );

  const m = rep.metrics as Record<string, Row>;
  const b2 = m.B2_221B ?? {};
  const b0 = m.B0_naive_alerts ?? {};
  const b1 = m.B1_time_window ?? {};
  const counts = m.counts ?? {};
  const nAtk = counts.attack_runs ?? 0;
  const nClean = counts.clean_runs ?? 0;
  const falseClean = Math.round((b2.clean_runs_with_false_incident ?? 0) * nClean);
  const tiers = (rep.by_tier ?? {}) as Record<string, Row>;
  const templates = (rep.by_template ?? {}) as Record<string, Row>;
  const misses = (rep.misses ?? []) as { seed: number; template: string; tier: string; why: string; params: Record<string, unknown> }[];
  const p = (x: number | undefined) => (x === undefined ? "n/a" : fmtPct(x));

  return (
    <main id="main" className="mx-auto max-w-[1180px] px-6 pt-10 pb-24 md:px-10">
      <header className="max-w-[860px]">
        <p className="text-[14px] text-slate">How 221B was tested</p>
        <h1 className="w-cond balance mt-1 text-[44px] leading-[1.04] font-[700] md:text-[52px]">
          {fmtNum(rep.n_scenarios)} generated cases, each scored against an answer key 221B never saw.
        </h1>
        <p className="pretty mt-4 text-[17px] leading-[1.5] text-graphite">
          {fmtNum(nAtk)} intrusions and {fmtNum(nClean)} clean weeks, across three difficulty levels. Each case is about{" "}
          {fmtNum(Math.round(b2.median_events ?? 0))} raw log lines, and 221B reads them the same way it reads an upload.
        </p>
        <p className="pretty mt-3 max-w-[72ch] rounded-[4px] border-l-2 border-watch bg-watch-soft px-4 py-3 text-[14px] text-graphite">
          What this does and does not show: the detectors were built while looking at this same scenario generator, so these numbers
          measure consistency and robustness to stealth, IP rotation, missing logs, clock skew and corrupted lines. They are not a
          real-world accuracy figure. The held-out test further down is the honest counterweight.
        </p>
      </header>

      <section aria-label="Headline results" className="mt-10 grid grid-cols-2 gap-x-8 gap-y-6 border-y border-rule py-7 md:grid-cols-4">
        {[
          [p(b2.detection_rate), "of intrusions found, with the compromised account inside the incident"],
          [p(b2.entry_ip_accuracy), "named the exact address the intruder logged in from"],
          [`${falseClean} of ${fmtNum(nClean)}`, "clean weeks wrongly reported as an intrusion"],
          [p(b2.stage_recall), "of the attack’s stages recovered, in the right order " + p(b2.stage_order_accuracy) + " of the time"],
        ].map(([v, label]) => (
          <div key={label}>
            <p className="w-cond nums text-[40px] leading-none font-[700]">{v}</p>
            <p className="pretty mt-2 text-[14px] leading-[1.4] text-slate">{label}</p>
          </div>
        ))}
      </section>

      {held && <HeldOut rep={held} />}

      <section aria-labelledby="three-h" className="mt-12">
        <h2 id="three-h" className="w-semi text-[22px] font-[650]">
          Same detector output, three ways of reading it
        </h2>
        <p className="pretty mt-1 max-w-[72ch] text-slate">
          All three start from the identical detector hits. Only the way they are grouped differs, so the gap is the value of linking
          steps by what each one needed.
        </p>
        <div className="mt-6 grid gap-10 md:grid-cols-2">
          <Bars
            title="Things an analyst has to review, per case"
            unit={(v) => (v >= 10 ? fmtNum(Math.round(v)) : v.toFixed(1))}
            rows={[
              { label: "Every hit is an alert", value: b0.units_to_review_per_run ?? 0 },
              { label: "Grouped by time", value: b1.units_to_review_per_run ?? 0 },
              { label: "221B incidents", value: b2.units_to_review_per_run ?? 0, ours: true },
            ]}
          />
          <Bars
            title="Share of the attack’s stages in the best single unit"
            unit={(v) => fmtPct(v)}
            rows={[
              { label: "Every hit is an alert", value: 1 / 9 },
              { label: "Grouped by time", value: b1.stage_recall ?? 0 },
              { label: "221B incidents", value: b2.stage_recall ?? 0, ours: true },
            ]}
          />
        </div>
        <table className="mt-7 w-full max-w-[860px] text-left text-[14px]">
          <caption className="sr-only">Comparison table</caption>
          <thead className="border-b border-rule text-[13px] text-slate">
            <tr>
              <th scope="col" className="py-2 font-[500]">Reading</th>
              <th scope="col" className="py-2 font-[500]">To review per case</th>
              <th scope="col" className="py-2 font-[500]">Stages in best unit</th>
              <th scope="col" className="py-2 font-[500]">Share that is real attack</th>
            </tr>
          </thead>
          <tbody className="nums">
            <tr className="border-b border-rule-soft">
              <th scope="row" className="py-2 font-[500]">Every hit is an alert</th>
              <td>{(b0.units_to_review_per_run ?? 0).toFixed(1)}</td>
              <td>one stage per alert</td>
              <td>{p(b0.precision)}</td>
            </tr>
            <tr className="border-b border-rule-soft">
              <th scope="row" className="py-2 font-[500]">Grouped by time (30 min)</th>
              <td>{(b1.units_to_review_per_run ?? 0).toFixed(1)}</td>
              <td>{p(b1.stage_recall)}</td>
              <td>{p(b1.purity)}</td>
            </tr>
            <tr>
              <th scope="row" className="py-2 font-[650] text-breach">221B</th>
              <td className="font-[650]">{(b2.units_to_review_per_run ?? 0).toFixed(1)}</td>
              <td className="font-[650]">{p(b2.stage_recall)}</td>
              <td className="font-[650]">{p(b2.purity)}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section aria-labelledby="tier-h" className="mt-12 grid max-w-[920px] gap-12">
        <div className="min-w-0">
          <h2 id="tier-h" className="w-semi text-[22px] font-[650]">
            By difficulty
          </h2>
          <table className="mt-3 w-full text-left text-[14px]">
            <thead className="border-b border-rule text-[13px] text-slate">
              <tr>
                <th scope="col" className="py-2 font-[500]">Level</th>
                <th scope="col" className="py-2 font-[500]">Cases</th>
                <th scope="col" className="py-2 font-[500]">Found</th>
                <th scope="col" className="py-2 font-[500]">Entry IP</th>
                <th scope="col" className="py-2 font-[500]">Stages</th>
                <th scope="col" className="py-2 font-[500] whitespace-nowrap">Log gaps flagged</th>
              </tr>
            </thead>
            <tbody className="nums">
              {Object.entries(tiers).map(([t, d]) => (
                <tr key={t} className="border-b border-rule-soft align-top">
                  <th scope="row" className="py-2 pr-2 font-[500]">
                    <span className="capitalize">{t}</span>
                    <span className="block max-w-[46ch] text-[12.5px] font-[400] text-slate">{TIER[t]?.split(": ")[1]}</span>
                  </th>
                  <td className="py-2">{d.runs}</td>
                  <td className="py-2">{p(d.detection_rate)}</td>
                  <td className="py-2">{p(d.entry_ip_accuracy)}</td>
                  <td className="py-2">{p(d.stage_recall)}</td>
                  <td className="py-2 whitespace-nowrap">{d.gap_recall === undefined ? "none injected" : p(d.gap_recall)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="min-w-0">
          <h2 className="w-semi text-[22px] font-[650]">By kind of case</h2>
          <table className="mt-3 w-full text-left text-[14px]">
            <thead className="border-b border-rule text-[13px] text-slate">
              <tr>
                <th scope="col" className="py-2 font-[500]">Case</th>
                <th scope="col" className="py-2 font-[500]">Cases</th>
                <th scope="col" className="py-2 font-[500]">Found</th>
                <th scope="col" className="py-2 font-[500]">Wrongly flagged</th>
              </tr>
            </thead>
            <tbody className="nums">
              {Object.entries(templates).map(([t, d]) => (
                <tr key={t} className="border-b border-rule-soft">
                  <th scope="row" className="py-2 font-[500]">{TEMPLATE[t] ?? t}</th>
                  <td className="py-2">{d.runs}</td>
                  <td className="py-2">{t === "T0" ? "n/a" : p(d.detection_rate)}</td>
                  <td className="py-2">
                    {t === "T0" ? p(d.clean_runs_with_false_incident) : `${(d.false_suspects_per_run ?? 0).toFixed(2)} innocent per case`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="miss-h" className="mt-12">
        <h2 id="miss-h" className="w-semi text-[22px] font-[650]">
          Where it fell short
        </h2>
        {misses.length === 0 ? (
          <p className="mt-2 text-slate">No misses or imperfections in this sweep.</p>
        ) : (
          <>
            <p className="pretty mt-1 max-w-[72ch] text-slate">
              The intruder was still found in every one of these. What went wrong is extra: an additional incident (typically an
              administrator logging in at an odd hour from a new network and touching hosts for the first time, which an analyst
              would also want to look at), or an innocent address named alongside the real one. Every case is reproducible from its
              seed; open one to see exactly what 221B concluded.
            </p>
            <ul className="mt-4 divide-y divide-rule-soft border-y border-rule-soft">
              {misses.map((x) => (
                <li key={x.seed} className="grid gap-x-4 gap-y-1 py-3 md:grid-cols-[110px_1fr_auto]">
                  <span className="nums font-mono text-[13px]">seed {x.seed}</span>
                  <span className="min-w-0 text-[14px]">
                    <span className="text-slate">
                      {TEMPLATE[x.template] ?? x.template}, {x.tier}.{" "}
                    </span>
                    <span className="break-words">{x.why}</span>
                  </span>
                  <button
                    type="button"
                    onClick={() => open(x.seed, x.params)}
                    disabled={opening !== null}
                    className="justify-self-start rounded-[4px] border border-rule px-3 py-1 text-[13px] hover:border-graphite disabled:opacity-50"
                  >
                    {opening === x.seed ? "Opening…" : "Open this case"}
                  </button>
                </li>
              ))}
            </ul>
          </>
        )}
      </section>

      <section aria-labelledby="how-h" className="mt-12 max-w-[860px]">
        <h2 id="how-h" className="w-semi text-[22px] font-[650]">
          How the test works
        </h2>
        <ol className="mt-3 list-decimal space-y-2 pl-5 text-[15px] leading-[1.5]">
          <li>A generator builds four days of activity for a small company and writes it as ordinary log files: auth.log, web access logs, network flows and an audit trail. The answer key goes into a separate file.</li>
          <li>221B receives only the log files, through the same path as an upload. Its code cannot import the generator; a test enforces this.</li>
          <li>The verdict is compared with the answer key: the entry address, the account, the host the data came from, the order of the steps, and any stretch of logs that was deliberately deleted.</li>
          <li>The two baselines use the exact same detector hits, so the difference is only in how the hits are linked.</li>
        </ol>
        <p className="mt-4 text-[14px] text-slate">
          Generated {new Date(rep.generated_at).toLocaleString("en-US", { timeZone: "UTC", dateStyle: "medium", timeStyle: "short" })} UTC, pipeline{" "}
          {rep.pipeline_version}, median {((b2.median_runtime_ms ?? 0) / 1000).toFixed(1)} s per case. Reproduce with{" "}
          <code className="font-mono text-[13px]">python -m eval.sweep</code>.
        </p>
      </section>
    </main>
  );
}

/** The held-out test: a template written after the engine was frozen, reported as-is. */
function HeldOut({ rep }: { rep: Report }) {
  const m = rep.metrics as Record<string, Row>;
  const b2 = m.B2_221B ?? {};
  const b1 = m.B1_time_window ?? {};
  const n = (m.counts ?? {}).attack_runs ?? 0;
  const found = Math.round((b2.detection_rate ?? 0) * n);
  const surfaced = Math.round((b2.surfaced_on_watchlist_only ?? 0) * n);
  return (
    <section aria-labelledby="held-h" className="mt-12 rounded-[4px] border border-rule bg-sheet p-6">
      <p className="text-[13px] text-slate">Held-out test, run once after the detection engine was frozen</p>
      <h2 id="held-h" className="w-cond balance mt-1 text-[30px] leading-[1.1] font-[700]">
        An insider stealing data with their own account: 221B surfaces the theft, but does not reconstruct it as an incident.
      </h2>
      <dl className="mt-5 grid gap-6 sm:grid-cols-3">
        <div>
          <dt className="text-[13.5px] text-slate">reconstructed as an incident</dt>
          <dd className="w-cond nums text-[36px] leading-none font-[700] text-breach">
            {found} of {fmtNum(n)}
          </dd>
        </div>
        <div>
          <dt className="text-[13.5px] text-slate">theft put on the high-priority watchlist, naming the right account or destination</dt>
          <dd className="w-cond nums text-[36px] leading-none font-[700]">
            {surfaced} of {fmtNum(n)}
          </dd>
        </div>
        <div>
          <dt className="text-[13.5px] text-slate">stages in the best unit: grouped by time vs 221B</dt>
          <dd className="w-cond nums text-[36px] leading-none font-[700]">
            {fmtPct(b1.stage_recall ?? 0)} <span className="text-[22px] text-slate">vs</span> {fmtPct(b2.stage_recall ?? 0)}
          </dd>
        </div>
      </dl>
      <p className="pretty mt-5 max-w-[78ch] text-[15px] leading-[1.55] text-graphite">
        This case has no break-in: a developer logs in normally, from home, in working hours, reaches the database server for the first
        time, packs a dump and sends it to an outside address. 221B links steps only when one step established what the next one needed,
        and here nothing established attacker access, so by design the steps stay single-stage findings. The exfiltration and the staging
        still reach the top of the watchlist every time, but a reviewer has to connect them. On this pattern, simply grouping by time does
        better. The fix we would make next is an insider anchor (first-ever access to a sensitive host followed by bulk data access in
        the same session); it has deliberately not been added, so this result stays a real held-out number.
      </p>
      <p className="mt-3 text-[13px] text-slate">
        {fmtNum(n)} cases across all three difficulty levels. Reproduce: <code className="font-mono">python -m eval.sweep --templates T3 --name benchmark_heldout</code>
      </p>
    </section>
  );
}

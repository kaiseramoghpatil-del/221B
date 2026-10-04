import { useRef, useState, type CSSProperties } from "react";
import Logo from "../components/Logo";
import { api, ApiError } from "../api/client";
import Tour from "../components/Tour";
import { AttackPathMini, demo, fmt, Funnel, Haystack, hhmm, seg, STAGE_LONG, stepsShown, useReplay } from "../components/HeroReplay";

type Busy = null | "demo" | "seed" | "upload";

const DEMO_SEED = demo.seed; // eval/demo_snapshot.py froze the replay from this same seed
const REPO = "https://github.com/kaiseramoghpatil-del/221B";
const inc = demo.incident;
const pct = (x: number) => `${Math.round(x * 100)}%`;

export default function Intake({ onOpen }: { onOpen: (caseId: string) => void }) {
  const [busy, setBusy] = useState<Busy>(null);
  const [error, setError] = useState<string | null>(null);
  const [genOpen, setGenOpen] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const { t, replay } = useReplay();

  async function run(kind: Busy, fn: () => Promise<{ case_id: string }>) {
    setBusy(kind);
    setError(null);
    try {
      const { case_id } = await fn();
      onOpen(case_id);
    } catch (e) {
      setError(e instanceof ApiError ? `The server refused this (${e.status}): ${e.message}` : "The analysis server is not reachable. Start it with: python -m uvicorn backend.api.app:app --port 8221");
      setBusy(null);
    }
  }
  const openDemo = () => run("demo", () => api.createScenario(DEMO_SEED, { template: "T1" }));

  return (
    <div className="min-h-full bg-paper text-graphite lg:grid lg:grid-cols-[208px_minmax(0,1fr)] xl:h-full xl:grid-cols-[208px_minmax(0,1fr)_288px]">
      <Sidebar busy={busy} onDemo={openDemo} />

      <main id="main" className="min-w-0 scroll-quiet xl:overflow-y-auto">
        <div className="mx-auto max-w-[1080px] px-5 pt-8 pb-10 md:px-10 md:pt-10">
          <section aria-labelledby="hero" data-tour="intro">
            <h1 id="hero" className="text-[clamp(56px,8vw,128px)] leading-[0.86] font-[820] tracking-[-0.025em]" style={{ fontStretch: "66%" }}>
              Find the intruder.
              <br />
              <span className="text-breach">Prove it.</span>
            </h1>
            <p className="pretty mt-6 max-w-[56ch] text-[19px] leading-[1.45]">
              221B reads raw logs, links the steps an attacker took, and shows the exact line that proves each one.
            </p>
            <p className="pretty mt-3 max-w-[60ch] text-[15px] leading-[1.5] text-slate">
              In the demo case, an outsider guessed passwords, logged in as the employee account <b className="text-breach">{inc.user}</b>, got root and
              copied {inc.gb_out}&nbsp;GB off the database server.
            </p>
            <div>
              <div className="mt-6 flex flex-wrap items-center gap-3" data-tour="cta">
                <button
                  type="button"
                  disabled={busy !== null}
                  onClick={openDemo}
                  className="rounded-[4px] bg-breach px-5 py-3 text-[16px] font-[700] text-white transition-colors hover:bg-[#8f1022] disabled:opacity-70"
                >
                  {busy === "demo" ? "Analysing the logs…" : "Open demo case"}
                </button>
                <button
                  type="button"
                  aria-expanded={genOpen}
                  aria-controls="gen"
                  onClick={() => setGenOpen((o) => !o)}
                  className="rounded-[4px] border border-rule px-4 py-3 font-[600] text-graphite transition-colors hover:border-graphite hover:text-graphite"
                >
                  Generate a scenario
                </button>
                <button
                  type="button"
                  disabled={busy !== null}
                  onClick={() => fileRef.current?.click()}
                  className="rounded-[4px] border border-rule px-4 py-3 font-[600] text-graphite transition-colors hover:border-graphite hover:text-graphite disabled:opacity-60"
                >
                  {busy === "upload" ? "Reading files…" : "Upload logs"}
                </button>
                <input
                  ref={fileRef}
                  type="file"
                  multiple
                  aria-label="Log files"
                  className="sr-only"
                  onChange={(e) => {
                    const files = Array.from(e.target.files ?? []);
                    if (files.length) run("upload", () => api.upload(files));
                  }}
                />
              </div>
              <p className="mt-3 text-[13.5px] text-slate">
                Opens in about 5 seconds. No sign-up.
              </p>
            </div>
          </section>
          {genOpen && <GenerateForm busy={busy} run={run} setError={setError} />}
          <p role="status" aria-live="polite" className="mt-3 min-h-[1.5em] text-[14px] text-breach">
            {error}
          </p>

          {/* the replay: stored results played back as a pipeline */}
          <section aria-labelledby="replay" className="mt-3 border-t border-rule pt-7">
            <div className="flex items-baseline justify-between gap-4">
              <h2 id="replay" className="text-[15px] font-[600] text-graphite">
                Demo case: from 48,753 log lines to one intruder
              </h2>
              <button type="button" onClick={replay} className="shrink-0 text-[13px] text-slate underline-offset-4 hover:text-graphite hover:underline">
                Replay
              </button>
            </div>
            <div className="mt-5" data-tour="funnel">
              <Funnel t={t} />
            </div>
            <div className="mt-8 grid gap-6 xl:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)]">
              <div data-tour="haystack" className="min-w-0">
                <Haystack t={t} />
              </div>
              <div className="min-w-0" data-tour="path">
                <AttackPathMini t={t} />
                <VerdictSlip visible={t >= 0.9} />
              </div>
            </div>
            <p className="mt-3 text-[12.5px] text-slate">
              Sped-up replay of the demo case's real results.
            </p>
          </section>

          <Proof />
        </div>
      </main>

      <Activity t={t} onReplay={replay} />
      <Tour
        id="start"
        steps={[
          { title: "What 221B does", body: "It reads server logs and finds the attacker hiding in normal traffic. Every claim points to a real log line." },
          { target: "funnel", title: "From noise to one answer", body: "48,753 log lines become 141 alerts. Only 11 connect into a real attack, so you review 1 incident instead of 141 alerts." },
          { target: "haystack", title: "The evidence", body: "These are real lines from the demo logs. The red ones are the attacker's steps, numbered in order." },
          { target: "path", title: "The attack path", body: "Each box is one step, placed on the server where it happened. The red line is the route the attacker took." },
          { target: "activity", title: "The steps in plain words", body: "The same 10 steps as a list, with times. Hover any step to see the exact finding." },
          { target: "cta", title: "Try it yourself", body: "Open the demo case to explore it, or generate a new attack with a random seed and check 221B against the hidden answer." },
        ]}
      />
    </div>
  );
}

/* ---------------- left: workspace navigation ---------------- */

function Sidebar({ busy, onDemo }: { busy: Busy; onDemo: () => void }) {
  const item = "block rounded-[3px] px-2.5 py-1.5 text-[14px] transition-colors hover:bg-rule-soft hover:text-graphite";
  return (
    <aside className="flex items-center gap-5 border-b border-rule bg-sheet px-5 py-3 lg:sticky lg:top-0 lg:row-span-2 lg:h-screen xl:row-span-1 lg:flex-col lg:items-stretch lg:gap-0 lg:border-r lg:border-b-0 lg:px-4 lg:py-6">
      {/* door-plate wordmark */}
      <a href="/" aria-label="221B, start" className="inline-flex flex-col self-start text-graphite">
        <Logo height={40} />
        <span className="mt-1.5 hidden pl-1 text-[11px] text-slate lg:block">find the intruder</span>
      </a>

      <nav aria-label="Workspace" className="flex gap-1 lg:mt-8 lg:flex-col">
        <a href="/" aria-current="page" className={`${item} bg-rule-soft font-[600] text-graphite`}>
          Start
        </a>
        <a href="/?page=verify" className={`${item} text-graphite`}>
          How it was tested
        </a>
        <a href={REPO} target="_blank" rel="noreferrer" className={`${item} hidden text-graphite sm:block`}>
          Source code
        </a>
      </nav>

      <div className="hidden lg:mt-8 lg:block">
        <h2 className="px-2.5 text-[12.5px] text-slate">Case files</h2>
        <button type="button" onClick={onDemo} disabled={busy !== null} className={`${item} mt-1 w-full text-left text-graphite disabled:opacity-60`}>
          <span className="block">Demo case</span>
          <span className="block font-mono text-[11px] text-slate">seed {demo.seed}, 1 incident</span>
        </button>
      </div>

      <figure className="mt-auto hidden px-2.5 lg:block">
        <blockquote className="text-[13px] leading-[1.45] text-slate italic">“It is a capital mistake to theorise before one has data.”</blockquote>
        <figcaption className="mt-1.5 text-[11.5px] text-mist">A Scandal in Bohemia</figcaption>
      </figure>
    </aside>
  );
}

/* ---------------- hero: the verdict, pinned like evidence ---------------- */

function VerdictSlip({ visible }: { visible: boolean }) {
  const facts = [
    [hhmm(demo.steps.find((s) => s.stage === "INITIAL_ACCESS")?.t ?? inc.t_start), "got in, UTC"],
    [String(demo.steps.length), "steps rebuilt"],
    [String(inc.hosts.length), "hosts reached"],
    [pct(inc.confidence), "confidence"],
  ];
  return (
    <aside
      aria-label="Verdict for the demo case"
      style={{ "--color-graphite": "#1c2128", "--color-slate": "#6b6457", "--color-rule": "#cfc7b5", "--color-breach": "#b4152b" } as CSSProperties}
      className={`relative mt-6 rotate-[-1.2deg] rounded-[3px] bg-[#ece6d8] px-5 pt-4 pb-4 text-graphite shadow-[0_24px_40px_-28px_rgba(0,0,0,0.85)] transition-[opacity,translate] duration-500 ${
        visible ? "translate-y-0 opacity-100" : "translate-y-3 opacity-0"
      }`}
    >
      <p className="flex justify-between text-[12.5px] text-slate">
        <span>Verdict, demo case</span>
        <span>seed {demo.seed}</span>
      </p>
      <p className="mt-2 text-[22px] leading-[1.1] font-[760]" style={{ fontStretch: "74%" }}>
        <span className="text-breach">{inc.user}</span>’s account was taken over from <span className="text-breach">{inc.entry_ip}</span>{" "}
        and used to reach db-01. {inc.gb_out}&nbsp;GB went back out.
      </p>
      <dl className="mt-4 grid grid-cols-4 gap-2 border-t border-rule pt-3">
        {facts.map(([v, k]) => (
          <div key={k}>
            <dt className="sr-only">{k}</dt>
            <dd className="w-cond nums text-[19px] leading-none font-[760]">{v}</dd>
            <dd aria-hidden="true" className="mt-1 text-[11.5px] text-slate">
              {k}
            </dd>
          </div>
        ))}
      </dl>
    </aside>
  );
}

/* ---------------- proof ---------------- */

function Proof() {
  const p = demo.proof;
  return (
    <section aria-labelledby="proof" className="mt-12 border-t border-rule pt-7">
      <h2 id="proof" className="sr-only">
        How well it works
      </h2>
      <div className="grid gap-8 sm:grid-cols-[1fr_1fr_1.15fr]">
        <div>
          <div className="w-cond nums text-[44px] leading-none font-[780] text-graphite">
            {p.found} / {p.attack_runs}
          </div>
          <p className="mt-2 max-w-[28ch] text-[14px] text-slate">generated intrusions found, scored against a hidden answer key</p>
        </div>
        <div>
          <div className="w-cond nums text-[44px] leading-none font-[780] text-graphite">
            {p.clean_flagged} / {p.clean_runs}
          </div>
          <p className="mt-2 max-w-[28ch] text-[14px] text-slate">clean weeks wrongly reported as an intrusion</p>
        </div>
        <p className="self-end text-[13.5px] leading-[1.5] text-slate">
          Where it falls short: in a held-out test of insider theft it reconstructed {p.heldout_reconstructed} of {p.heldout_runs} cases, though
          all {p.heldout_watchlisted} reached the high-priority watchlist.{" "}
          <a href="/?page=verify" className="text-graphite underline underline-offset-4 hover:text-graphite">
            See how it was tested
          </a>
        </p>
      </div>
    </section>
  );
}

/* ---------------- right: activity ---------------- */

function Activity({ t, onReplay }: { t: number; onReplay: () => void }) {
  const shown = stepsShown(t);
  const f = demo.funnel;
  const rows = [
    `Read ${fmt(f.events)} events, ${demo.parse.lines_quarantined} unreadable`,
    `Raised ${fmt(f.signals)} detector signals`,
    `Linked ${f.linked_signals} signals by cause`,
    `Admitted ${f.incidents} incident, ${f.watchlist} watchlist item`,
  ];
  return (
    <aside aria-label="Activity" data-tour="activity" className="border-t border-rule bg-sheet px-5 py-6 lg:col-start-2 xl:col-start-auto xl:h-full xl:overflow-y-auto xl:border-t-0 xl:border-l scroll-quiet">
      <div className="flex items-center justify-between">
        <h2 className="text-[14px] font-[600] text-graphite">Activity</h2>
        <span className="flex items-center gap-1.5 text-[12px] text-slate">
          <span className={`size-1.5 rounded-full ${t < 1 ? "animate-pulse bg-breach" : "bg-mist"}`} />
          {t < 1 ? "Replaying" : "Replayed"}
        </span>
      </div>
      <p className="mt-1 text-[12.5px] text-slate">Stored run of the demo case, seed {demo.seed}</p>

      <ol className="mt-5 space-y-2.5 text-[13px]">
        {rows.map((r, i) => {
          const done = seg(t, 0.03 + i * 0.1, 0.28 + i * 0.1) >= 1;
          return (
            <li key={r} className={`flex gap-2.5 transition-colors ${done ? "text-graphite" : "text-mist"}`}>
              <span aria-hidden="true" className={`mt-[7px] size-1.5 shrink-0 rounded-full ${done ? "bg-graphite" : "bg-rule"}`} />
              {r}
            </li>
          );
        })}
      </ol>

      <h3 className="mt-7 text-[12.5px] text-slate">Reconstructed steps</h3>
      <ol className="mt-2 space-y-px">
        {demo.steps.map((s) => {
          const on = s.order <= shown;
          return (
            <li key={s.order} title={s.text} className={`grid grid-cols-[18px_40px_1fr] gap-1.5 py-1 text-[12.5px] transition-opacity duration-200 ${on ? "opacity-100" : "opacity-25"}`}>
              <span className="nums text-right font-[700] text-breach">{s.order}</span>
              <span className="nums font-mono text-[11.5px] leading-[19px] text-slate">{hhmm(s.t)}</span>
              <span className="min-w-0 truncate text-graphite">
                {STAGE_LONG[s.stage] ?? s.stage}
                <span className="text-slate">, {s.host}</span>
              </span>
            </li>
          );
        })}
      </ol>

      <button type="button" onClick={onReplay} className="mt-6 text-[13px] text-slate underline-offset-4 hover:text-graphite hover:underline">
        Replay the run
      </button>
    </aside>
  );
}

/* ---------------- generate a scenario (same knobs as before) ---------------- */

function GenerateForm({
  busy,
  run,
  setError,
}: {
  busy: Busy;
  run: (k: Busy, fn: () => Promise<{ case_id: string }>) => void;
  setError: (e: string | null) => void;
}) {
  const [seed, setSeed] = useState("");
  const [template, setTemplate] = useState<"T1" | "T2" | "T0" | "T3">("T1");
  const [stealth, setStealth] = useState(0.5);
  const [rotation, setRotation] = useState(1);
  const field = "mt-1 block w-full rounded-[4px] border border-rule bg-sheet px-2.5 py-2 text-graphite focus-visible:border-graphite";
  return (
    <form
      id="gen"
      className="mt-5 max-w-[560px] rounded-[4px] border border-rule bg-sheet p-5"
      onSubmit={(e) => {
        e.preventDefault();
        const n = Number(seed);
        if (!Number.isInteger(n) || n < 0) {
          setError("Enter a whole number for the seed, for example 4127.");
          return;
        }
        run("seed", () => api.createScenario(n, { template, stealth, ip_rotation: rotation }));
      }}
    >
      <p className="text-[14px] text-graphite">Pick any number to generate a case nobody has seen. The answer key stays hidden until you reveal it.</p>
      <div className="mt-4 grid grid-cols-[1fr_auto] items-end gap-2">
        <label className="block">
          <span className="text-[13px] text-slate">Seed</span>
          <input
            name="seed"
            inputMode="numeric"
            autoComplete="off"
            spellCheck={false}
            value={seed}
            onChange={(e) => setSeed(e.target.value.replace(/[^0-9]/g, ""))}
            placeholder="e.g. 4127…"
            className={`${field} nums font-mono text-[15px]`}
          />
        </label>
        <button
          type="button"
          onClick={() => setSeed(String(Math.floor(Math.random() * 99999) + 1))}
          className="rounded-[4px] border border-rule px-3 py-2 text-graphite hover:border-graphite"
        >
          Random
        </button>
      </div>
      <div className="mt-3 grid grid-cols-2 gap-3 text-[14px]">
        <label className="block">
          <span className="text-[13px] text-slate">Attack</span>
          <select name="template" value={template} onChange={(e) => setTemplate(e.target.value as "T1" | "T2" | "T0" | "T3")} className={field}>
            <option value="T1">Stolen credential</option>
            <option value="T2">Password guessing</option>
            <option value="T0">No attack (clean)</option>
            <option value="T3">Insider theft (held-out test)</option>
          </select>
        </label>
        <label className="block">
          <span className="text-[13px] text-slate">Attacker IPs</span>
          <select name="rotation" value={rotation} onChange={(e) => setRotation(Number(e.target.value))} className={field}>
            {[1, 3, 10, 40].map((n) => (
              <option key={n} value={n}>
                {n === 1 ? "1 address" : `${n} rotating`}
              </option>
            ))}
          </select>
        </label>
      </div>
      <label className="mt-3 block">
        <span className="flex justify-between text-[13px] text-slate">
          <span>Stealth</span>
          <span className="nums">{stealth < 0.34 ? "fast and noisy" : stealth < 0.67 ? "moderate" : "slow and quiet"}</span>
        </span>
        <input
          type="range"
          name="stealth"
          min={0}
          max={1}
          step={0.05}
          value={stealth}
          onChange={(e) => setStealth(Number(e.target.value))}
          className="mt-2 w-full accent-[#e0283f]"
        />
      </label>
      <button
        type="submit"
        disabled={busy !== null || !seed}
        className="mt-5 rounded-[4px] border border-graphite px-4 py-2.5 font-[600] text-graphite transition-colors hover:bg-graphite hover:text-paper disabled:opacity-50"
      >
        {busy === "seed" ? "Generating and analysing…" : "Generate and investigate"}
      </button>
    </form>
  );
}

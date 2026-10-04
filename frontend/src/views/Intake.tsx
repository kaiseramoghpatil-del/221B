import { useRef, useState } from "react";
import { api, ApiError } from "../api/client";

type Busy = null | "demo" | "seed" | "upload";

const DEMO_SEED = 1;

export default function Intake({ onOpen }: { onOpen: (caseId: string) => void }) {
  const [busy, setBusy] = useState<Busy>(null);
  const [error, setError] = useState<string | null>(null);
  const [seed, setSeed] = useState("");
  const [template, setTemplate] = useState<"T1" | "T2" | "T0" | "T3">("T1");
  const [stealth, setStealth] = useState(0.5);
  const [rotation, setRotation] = useState(1);
  const fileRef = useRef<HTMLInputElement>(null);

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

  const randomSeed = () => setSeed(String(Math.floor(Math.random() * 99999) + 1));

  return (
    <main id="main" className="min-h-full">
      <div className="mx-auto max-w-[1180px] px-6 pt-8 pb-24 md:px-10">
        <header className="max-w-[760px]">
          <h1 className="w-cond text-[88px] leading-[0.9] font-[750] tracking-[-0.02em]">221B</h1>
          <p className="balance mt-6 text-[26px] leading-[1.25] font-[450] text-graphite">
            Give it a pile of logs. It tells you who got in, how, what they touched, and shows the proof line by line.
          </p>
          <p className="pretty mt-4 max-w-[62ch] text-slate">
            Detections are deterministic rules and baselines. They are linked only when one step makes the next possible, so a loud
            attacker who never got in stays loud and harmless, and a quiet one who did is reconstructed end to end.
          </p>
        </header>

        <section aria-labelledby="start" className="mt-14 grid gap-px overflow-hidden rounded-[4px] border border-rule bg-rule md:grid-cols-3">
          <h2 id="start" className="sr-only">
            Start an investigation
          </h2>

          <div className="flex flex-col bg-sheet p-6">
            <h3 className="w-semi text-[19px] font-[650]">Open the demo case</h3>
            <p className="mt-2 flex-1 text-slate">
              Four days of logs from a six-server company: tens of thousands of events, five innocent look-alikes, and one intruder.
            </p>
            <button
              type="button"
              disabled={busy !== null}
              onClick={() => run("demo", () => api.createScenario(DEMO_SEED, { template: "T1" }))}
              className="mt-6 self-start rounded-[4px] bg-graphite px-4 py-2.5 font-[600] text-white transition-colors hover:bg-black disabled:opacity-60"
            >
              {busy === "demo" ? "Analysing the logs…" : "Open demo case"}
            </button>
          </div>

          <form
            className="flex flex-col bg-sheet p-6"
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
            <h3 className="w-semi text-[19px] font-[650]">Generate a case nobody has seen</h3>
            <p className="mt-2 text-slate">Pick any number. The answer key stays hidden until you reveal it.</p>
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
                  className="nums mt-1 block w-full rounded-[4px] border border-rule bg-paper px-3 py-2 font-mono text-[15px] focus-visible:border-graphite"
                />
              </label>
              <button type="button" onClick={randomSeed} className="rounded-[4px] border border-rule px-3 py-2 hover:border-graphite">
                Random
              </button>
            </div>
            <div className="mt-3 grid grid-cols-2 gap-3 text-[14px]">
              <label className="block">
                <span className="text-[13px] text-slate">Attack</span>
                <select
                  name="template"
                  value={template}
                  onChange={(e) => setTemplate(e.target.value as "T1" | "T2" | "T0" | "T3")}
                  className="mt-1 block w-full rounded-[4px] border border-rule bg-paper px-2 py-2 text-graphite"
                >
                  <option value="T1">Stolen credential</option>
                  <option value="T2">Password guessing</option>
                  <option value="T0">No attack (clean)</option>
                  <option value="T3">Insider theft (held-out test)</option>
                </select>
              </label>
              <label className="block">
                <span className="text-[13px] text-slate">Attacker IPs</span>
                <select
                  name="rotation"
                  value={rotation}
                  onChange={(e) => setRotation(Number(e.target.value))}
                  className="mt-1 block w-full rounded-[4px] border border-rule bg-paper px-2 py-2 text-graphite"
                >
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
                className="mt-2 w-full accent-graphite"
              />
            </label>
            <button
              type="submit"
              disabled={busy !== null || !seed}
              className="mt-5 self-start rounded-[4px] border border-graphite px-4 py-2.5 font-[600] transition-colors hover:bg-graphite hover:text-white disabled:opacity-50"
            >
              {busy === "seed" ? "Generating and analysing…" : "Generate and investigate"}
            </button>
          </form>

          <div className="flex flex-col bg-sheet p-6">
            <h3 className="w-semi text-[19px] font-[650]">Investigate your own logs</h3>
            <p className="mt-2 flex-1 text-slate">
              Linux auth.log, nginx or Apache access logs, and CSV or JSON-lines exports. Lines that cannot be read are listed, never
              silently dropped.
            </p>
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
            <button
              type="button"
              disabled={busy !== null}
              onClick={() => fileRef.current?.click()}
              className="mt-6 self-start rounded-[4px] border border-graphite px-4 py-2.5 font-[600] transition-colors hover:bg-graphite hover:text-white disabled:opacity-50"
            >
              {busy === "upload" ? "Reading files…" : "Choose log files"}
            </button>
          </div>
        </section>

        <p role="status" aria-live="polite" className="mt-4 min-h-[1.5em] text-[14px] text-breach">
          {error}
        </p>
      </div>
    </main>
  );
}

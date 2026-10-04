import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  ApiError,
  type AttackGraph,
  type CaseSummary,
  type Claim,
  type Dismissal,
  type Incident,
  type IncidentDetail,
  type NaiveAlert,
  type Suspect,
} from "../api/client";
import AttackPath from "../components/AttackPath";
import { Findings, NotFlagged, ScoreNote } from "../components/Dossier";
import EvidenceDrawer, { type DrawerTarget } from "../components/EvidenceDrawer";
import IsolatedAlerts from "../components/IsolatedAlerts";
import Rail from "../components/Rail";
import RevealDialog from "../components/RevealDialog";
import { Funnel, Verdict } from "../components/Verdict";
import Waterfall from "../components/Waterfall";
import { buildBoard, type Cell } from "../lib/board";
import { STAGE, entityLabel, fmtTime } from "../lib/format";
import type { UrlState } from "../lib/url";

type CaseData = { summary: CaseSummary; incidents: Incident[]; suspects: Suspect[]; dismissals: Dismissal[]; naive: NaiveAlert[] };

const reduceMotion = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

export default function CaseView({ url, setUrl }: { url: UrlState; setUrl: (p: Partial<UrlState>, replace?: boolean) => void }) {
  const caseId = url.case!;
  const [data, setData] = useState<CaseData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [graph, setGraph] = useState<AttackGraph | null>(null);
  const [focusStep, setFocusStep] = useState<string | null>(null);
  const [shown, setShown] = useState<number>(Number.MAX_SAFE_INTEGER);
  const [playing, setPlaying] = useState(false);
  const timer = useRef<number | null>(null);

  useEffect(() => {
    let live = true;
    setData(null);
    setError(null);
    Promise.all([api.summary(caseId), api.incidents(caseId), api.suspects(caseId), api.dismissals(caseId), api.naive(caseId)])
      .then(([summary, inc, sus, dis, nv]) => {
        if (!live) return;
        setData({ summary, incidents: inc.incidents, suspects: sus.suspects, dismissals: dis.dismissals, naive: nv.alerts });
      })
      .catch((e) => live && setError(e instanceof ApiError && e.status === 404 ? "This case no longer exists on the server (it restarted). Open a new one." : String(e.message ?? e)));
    return () => {
      live = false;
    };
  }, [caseId]);

  const firstIncident = data?.incidents.find((i) => i.status === "incident")?.id;
  const incidentId = url.incident ?? firstIncident;

  useEffect(() => {
    if (!incidentId) return;
    let live = true;
    setDetail(null);
    setGraph(null);
    Promise.all([api.incident(caseId, incidentId), api.replay(caseId, incidentId)])
      .then(([d, g]) => {
        if (!live) return;
        setDetail(d);
        setGraph(g);
        setShown(Number.MAX_SAFE_INTEGER);
      })
      .catch((e) => live && setError(String(e.message ?? e)));
    return () => {
      live = false;
    };
  }, [caseId, incidentId]);

  const board = useMemo(() => (detail ? buildBoard(detail.incident.steps ?? [], graph, detail.claims) : null), [detail, graph]);
  const nSteps = board?.cells.length ?? 0;
  const visible = Math.min(shown, nSteps);

  const stop = useCallback(() => {
    if (timer.current) window.clearInterval(timer.current);
    timer.current = null;
    setPlaying(false);
  }, []);
  const play = useCallback(() => {
    if (!nSteps) return;
    if (reduceMotion()) {
      setShown(nSteps);
      return;
    }
    stop();
    setShown(0);
    setPlaying(true);
    let k = 0;
    timer.current = window.setInterval(() => {
      k += 1;
      setShown(k);
      if (k >= nSteps) {
        if (timer.current) window.clearInterval(timer.current);
        timer.current = null;
        setPlaying(false);
      }
    }, 1100);
  }, [nSteps, stop]);
  useEffect(() => stop, [stop]);

  // ---- evidence drawer, deep-linked through ?claim= / ?dismissal=
  const drawer: DrawerTarget | null = useMemo(() => {
    if (!detail) return null;
    if (url.claim) {
      const claim = detail.claims.find((c) => c.id === url.claim);
      if (!claim) return null;
      const step = (detail.incident.steps ?? []).find((s) => s.id === claim.step_id);
      const ids = new Set(step?.signal_ids ?? []);
      return { kind: "claim", claim, signals: (detail.signals ?? []).filter((s) => ids.has(s.id)), stage: step?.stage };
    }
    if (url.dismissal && data) {
      const d = data.dismissals.find((x) => x.id === url.dismissal);
      return d ? { kind: "dismissal", d } : null;
    }
    return null;
  }, [detail, data, url.claim, url.dismissal]);
  const openClaim = (c: Claim) => setUrl({ claim: c.id, dismissal: undefined });
  const openCell = (cell: Cell) => cell.claim && openClaim(cell.claim);
  const closeDrawer = useCallback(() => setUrl({ claim: undefined, dismissal: undefined }), [setUrl]);

  if (error)
    return (
      <main id="main" className="mx-auto max-w-[720px] px-6 py-20">
        <h1 className="w-cond text-[34px] font-[700]">This case could not be opened</h1>
        <p className="mt-3 text-slate">{error}</p>
        <a href="/" className="mt-6 inline-block rounded-[4px] bg-graphite px-4 py-2 font-[600] text-white">
          Start a new investigation
        </a>
      </main>
    );
  if (!data)
    return (
      <main id="main" className="grid min-h-full place-items-center">
        <p aria-live="polite" className="text-slate">
          Loading the case…
        </p>
      </main>
    );

  const isAlerts = url.view === "alerts";
  const inc = detail?.incident;
  const attackerLabels = data.suspects
    .filter((s) => inc?.entities.includes(s.entity.id) && (s.role === "attacker_infra" || s.role === "compromised_account"))
    .map((s) => entityLabel(s.entity.id));
  const signalLabel = (sid: string) => {
    const s = detail?.signals?.find((x) => x.id === sid);
    return s ? `${s.detector} ${s.title}` : sid;
  };
  const currentStep = board && visible > 0 ? board.cells[visible - 1].step : null;

  return (
    <div className="min-h-full">
      <header className="sticky top-0 z-30 border-b border-rule bg-paper/95 backdrop-blur">
        <div className="mx-auto flex max-w-[1560px] flex-wrap items-center gap-x-6 gap-y-2 px-5 py-3">
          <a href="/" className="w-cond text-[24px] leading-none font-[750] tracking-[-0.01em] hover:text-breach" aria-label="221B, start a new investigation">
            221B
          </a>
          <p className="min-w-0 truncate text-[14px] text-slate">
            {data.summary.name}
            {data.summary.parse_report ? `, ${data.summary.parse_report.files.length} log files` : ""}
          </p>
          <div role="group" aria-label="View" className="ml-auto flex rounded-[4px] border border-rule bg-sheet p-0.5 text-[13.5px]">
            {[
              ["Reconstructed", undefined],
              ["Isolated alerts", "alerts"],
            ].map(([label, v]) => (
              <button
                key={label}
                type="button"
                aria-pressed={url.view === v}
                onClick={() => setUrl({ view: v as "alerts" | undefined, claim: undefined })}
                className={`rounded-[3px] px-3 py-1.5 transition-colors ${url.view === v ? "bg-graphite text-white" : "text-slate hover:text-graphite"}`}
              >
                {label}
              </button>
            ))}
          </div>
          {data.summary.source === "scenario" && (
            <button
              type="button"
              onClick={() => setUrl({ reveal: "1" })}
              className="rounded-[4px] border border-graphite px-3 py-1.5 text-[13.5px] font-[600] transition-colors hover:bg-graphite hover:text-white"
            >
              Reveal the answer key
            </button>
          )}
        </div>
        <div className="mx-auto max-w-[1560px] px-5 pb-3">
          <Funnel summary={data.summary} />
        </div>
      </header>

      <div className="mx-auto grid max-w-[1560px] grid-cols-[minmax(0,1fr)] gap-7 px-5 py-6 lg:grid-cols-[236px_minmax(0,1fr)] xl:grid-cols-[236px_minmax(0,1fr)_372px]">
        <aside className="order-3 lg:order-1">
          <Rail incidents={data.incidents} selected={incidentId} onSelect={(id) => setUrl({ incident: id, view: undefined, claim: undefined })} suspects={data.suspects} />
        </aside>

        <main id="main" className="order-1 min-w-0 lg:order-2">
          {isAlerts ? (
            <IsolatedAlerts alerts={data.naive} incidents={data.incidents} onPick={(id) => setUrl({ incident: id, view: undefined })} />
          ) : !incidentId ? (
            <section aria-labelledby="clean-h" className="border-b border-rule pb-6">
              <h1 id="clean-h" className="w-cond balance text-[38px] leading-[1.06] font-[700] md:text-[42px]">
                No intrusion found in {data.summary.funnel.events.toLocaleString("en-US")} events.
              </h1>
              <p className="pretty mt-3 max-w-[66ch] text-slate">
                {data.summary.funnel.signals} detector hits, but none of them connect into a second attack stage: nothing that one
                step made possible was followed by another. {data.summary.funnel.watchlist > 0
                  ? `${data.summary.funnel.watchlist} single-stage findings are on the watchlist on the left if you want to look anyway.`
                  : "Nothing is on the watchlist either."}
              </p>
              <NotFlagged dismissals={data.dismissals} onOpen={(d) => setUrl({ dismissal: d.id, claim: undefined })} />
            </section>
          ) : !detail || !board ? (
            <p aria-live="polite" className="text-slate">
              Reconstructing…
            </p>
          ) : (
            <>
              <Verdict detail={detail} suspects={data.suspects} />

              <section aria-labelledby="exa-h" className="mt-6">
                <div className="flex flex-wrap items-end gap-x-4 gap-y-2">
                  <div>
                    <h2 id="exa-h" className="w-semi text-[19px] font-[650]">
                      Exhibit A. The path through the network
                    </h2>
                    <p className="text-[13.5px] text-slate">Rows are places, columns are attack stages. The red thread is the order things happened.</p>
                  </div>
                  <div className="ml-auto flex items-center gap-3">
                    <button
                      type="button"
                      onClick={playing ? stop : play}
                      className="rounded-[4px] bg-breach px-3.5 py-2 text-[14px] font-[600] text-white transition-colors hover:bg-[#8f0f21]"
                    >
                      {playing ? "Pause" : visible >= nSteps ? (inc?.status === "incident" ? "Replay the attack" : "Replay") : "Resume"}
                    </button>
                  </div>
                </div>
                <div className="scroll-quiet mt-3 overflow-x-auto rounded-[4px] border border-rule bg-sheet p-3">
                  <div className="min-w-[720px]">
                  <AttackPath board={board} shown={visible} focusStep={focusStep} onFocus={setFocusStep} onOpen={openCell} />
                  </div>
                  <label className="mt-2 flex items-center gap-3 text-[13px] text-slate">
                    <span className="sr-only">Replay position</span>
                    <input
                      type="range"
                      min={0}
                      max={nSteps}
                      step={1}
                      value={visible}
                      onChange={(e) => {
                        stop();
                        setShown(Number(e.target.value));
                      }}
                      className="w-full accent-[var(--color-breach)]"
                    />
                    <span aria-live="polite" className="nums w-[230px] shrink-0 text-right">
                      {currentStep ? `Step ${visible} of ${nSteps}: ${STAGE[currentStep.stage].plain}, ${fmtTime(currentStep.t_start)}` : "Before the attack"}
                    </span>
                  </label>
                </div>
              </section>

              <section aria-labelledby="exb-h" className="mt-7">
                <h2 id="exb-h" className="w-semi text-[19px] font-[650]">
                  Exhibit B. When it happened
                </h2>
                <p className="text-[13.5px] text-slate">The same steps on a real clock. Hatched stretches are periods the logs are missing.</p>
                <div className="scroll-quiet mt-3 overflow-x-auto rounded-[4px] border border-rule bg-sheet p-3">
                  <div className="min-w-[600px]">
                  <Waterfall board={board} gaps={inc?.gaps ?? []} shown={visible} focusStep={focusStep} onFocus={setFocusStep} />
                  </div>
                </div>
              </section>

              {inc?.status === "incident" && (
                <NotFlagged dismissals={data.dismissals} onOpen={(d) => setUrl({ dismissal: d.id, claim: undefined })} />
              )}

              {inc && (inc.entry_hypotheses ?? []).length > 1 && (
                <p className="mt-4 text-[14px] text-slate">
                  Two ways in are plausible: {(inc.entry_hypotheses ?? []).map((h) => `${h.description} (${Math.round(h.probability * 100)}%)`).join("; ")}.
                </p>
              )}
            </>
          )}
        </main>

        <aside aria-label="Findings and evidence" className="order-2 min-w-0 lg:order-3 lg:col-span-2 xl:col-span-1">
          {detail && !isAlerts && (
            <>
              <Findings detail={detail} attacker={attackerLabels} focusStep={focusStep} onFocus={setFocusStep} onOpenClaim={openClaim} activeClaim={url.claim} />
              <ScoreNote detail={detail} labelOf={signalLabel} />
            </>
          )}
        </aside>
      </div>

      <EvidenceDrawer caseId={caseId} target={drawer} onClose={closeDrawer} />
      {data.summary.source === "scenario" && <RevealDialog caseId={caseId} open={url.reveal === "1"} onClose={() => setUrl({ reveal: undefined })} />}
    </div>
  );
}

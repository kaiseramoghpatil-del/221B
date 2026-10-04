/**
 * Guided tour: a small card in the corner that steps through the screen and outlines the part it is talking about.
 * It never covers the page with a backdrop, so everything stays clickable while it is open.
 */
import { useEffect, useState } from "react";

export type TourStep = { target?: string; title: string; body: string };

export default function Tour({ id, steps }: { id: string; steps: TourStep[] }) {
  const key = `221b-tour-${id}`;
  const [open, setOpen] = useState(() => {
    try {
      return localStorage.getItem(key) !== "seen";
    } catch {
      return true;
    }
  });
  const [i, setI] = useState(0);
  const step = steps[i];

  const close = () => {
    setOpen(false);
    try {
      localStorage.setItem(key, "seen");
    } catch {
      /* private mode: the tour just shows again next time */
    }
  };

  // outline the step's target and bring it into view
  useEffect(() => {
    if (!open || !step.target) return;
    const el = document.querySelector<HTMLElement>(`[data-tour="${step.target}"]`);
    if (!el) return;
    el.classList.add("tour-focus");
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    el.scrollIntoView({ block: "center", behavior: reduce ? "auto" : "smooth" });
    return () => el.classList.remove("tour-focus");
  }, [open, step]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLSelectElement) return;
      if (e.key === "Escape") close();
      if (e.key === "ArrowRight") setI((n) => Math.min(steps.length - 1, n + 1));
      if (e.key === "ArrowLeft") setI((n) => Math.max(0, n - 1));
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => {
          setI(0);
          setOpen(true);
        }}
        className="fixed right-4 bottom-4 z-40 rounded-full border border-rule bg-sheet px-4 py-2 text-[13.5px] font-[600] shadow-[0_8px_24px_-12px_rgba(0,0,0,0.6)] hover:border-graphite"
      >
        Take the tour
      </button>
    );
  }

  const last = i === steps.length - 1;
  return (
    <div
      role="dialog"
      aria-label="Guided tour"
      aria-live="polite"
      className="fixed right-4 bottom-4 z-40 w-[min(340px,calc(100vw-32px))] rounded-[6px] border border-rule bg-sheet p-4 shadow-[0_18px_40px_-18px_rgba(0,0,0,0.7)]"
    >
      <div className="flex items-center justify-between text-[12.5px] text-slate">
        <span className="nums">
          {i + 1} of {steps.length}
        </span>
        <button type="button" onClick={close} className="hover:text-graphite" aria-label="Close the tour">
          Skip
        </button>
      </div>
      <h2 className="mt-1.5 text-[17px] leading-[1.25] font-[700]">{step.title}</h2>
      <p className="mt-1 text-[14px] leading-[1.45] text-slate">{step.body}</p>
      <div className="mt-4 flex items-center justify-between">
        <div className="flex gap-1.5" aria-hidden="true">
          {steps.map((_, n) => (
            <button
              key={n}
              type="button"
              tabIndex={-1}
              onClick={() => setI(n)}
              className={`h-1.5 rounded-full transition-all ${n === i ? "w-5 bg-breach" : "w-1.5 bg-rule hover:bg-mist"}`}
            />
          ))}
        </div>
        <div className="flex gap-2">
          {i > 0 && (
            <button type="button" onClick={() => setI(i - 1)} className="rounded-[4px] px-3 py-1.5 text-[13.5px] text-slate hover:text-graphite">
              Back
            </button>
          )}
          <button
            type="button"
            onClick={() => (last ? close() : setI(i + 1))}
            className="rounded-[4px] bg-graphite px-3.5 py-1.5 text-[13.5px] font-[600] text-paper hover:bg-white"
          >
            {last ? "Done" : "Next"}
          </button>
        </div>
      </div>
    </div>
  );
}

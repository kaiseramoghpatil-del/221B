import { useCallback, useEffect, useState } from "react";

/** URL is the source of truth for case / incident / view / evidence (deep-linkable, back button works). */
export type UrlState = { case?: string; incident?: string; view?: "alerts"; claim?: string; dismissal?: string; reveal?: string; page?: "verify" };

function read(): UrlState {
  const p = new URLSearchParams(window.location.search);
  const out: UrlState = {};
  for (const k of ["case", "incident", "view", "claim", "dismissal", "reveal", "page"] as const) {
    const v = p.get(k);
    if (v) (out as Record<string, string>)[k] = v;
  }
  return out;
}

export function useUrlState(): [UrlState, (patch: Partial<UrlState>, replace?: boolean) => void] {
  const [state, setState] = useState<UrlState>(read);
  useEffect(() => {
    const on = () => setState(read());
    window.addEventListener("popstate", on);
    return () => window.removeEventListener("popstate", on);
  }, []);
  const update = useCallback((patch: Partial<UrlState>, replace = false) => {
    const next = { ...read(), ...patch };
    const p = new URLSearchParams();
    Object.entries(next).forEach(([k, v]) => v && p.set(k, v));
    const url = `${window.location.pathname}${p.toString() ? `?${p}` : ""}`;
    if (replace) window.history.replaceState(null, "", url);
    else window.history.pushState(null, "", url);
    setState(next);
  }, []);
  return [state, update];
}

import { useLayoutEffect, useRef, useState } from "react";

/** Container width: measured once on mount (in an effect, not during render) and kept current via ResizeObserver. */
export function useWidth<T extends HTMLElement>(fallback = 760) {
  const ref = useRef<T>(null);
  const [w, setW] = useState(fallback);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    setW(Math.max(320, Math.round(el.getBoundingClientRect().width)));
    const ro = new ResizeObserver(([e]) => setW(Math.max(320, Math.round(e.contentRect.width))));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, w] as const;
}

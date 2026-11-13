import { useCallback, useEffect, useId, useRef, useState } from "react";
import type { CSSProperties } from "react";

// dropdown's list, floating over the page
export function useFloatingList(maxHeight: number) {
  const [open, setOpen] = useState(false);
  const [place, setPlace] = useState<CSSProperties | null>(null);
  const wrap = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const listId = useId();

  const placeList = useCallback(() => {
    const r = trigger.current?.getBoundingClientRect();
    if (!r) return;
    const below = window.innerHeight - r.bottom - 8;
    const above = r.top - 8;
    const up = below < 200 && above > below;
    setPlace({
      position: "fixed",
      left: Math.min(r.left, window.innerWidth - 16 - Math.min(416, window.innerWidth - 32)),
      minWidth: r.width,
      ...(up ? { bottom: window.innerHeight - r.top + 4 } : { top: r.bottom + 4 }),
      maxHeight: Math.min(maxHeight, up ? above : below),
    });
  }, [maxHeight]);

  useEffect(() => {
    if (!open) return;
    window.addEventListener("scroll", placeList, true);
    window.addEventListener("resize", placeList);
    return () => {
      window.removeEventListener("scroll", placeList, true);
      window.removeEventListener("resize", placeList);
    };
  }, [open, placeList]);

  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      const t = e.target as Node;
      if (!wrap.current?.contains(t) && !list.current?.contains(t)) setOpen(false);
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);

  const show = () => {
    placeList();
    setOpen(true);
  };
  // the focus goes back to the button, unless it is moving on (Tab)
  const close = (refocus = true) => {
    setOpen(false);
    if (refocus) trigger.current?.focus();
  };

  return { open, place, wrap, trigger, list, listId, show, close };
}// useFloatingList

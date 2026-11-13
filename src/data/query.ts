import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useScanStore } from "../stores/scanStore";

// the backend holds the scans and builds what a page shows
const cache = new Map<string, unknown>();
const pending = new Map<string, Promise<unknown>>();
let cachedFor = "";

function openFilesKey(): string {
  return useScanStore.getState().files.map((f) => f.id).join(",");
}// openFilesKey

export function ask<T>(cmd: string, args: Record<string, unknown> = {}): Promise<T> {
  const files = openFilesKey();
  if (files !== cachedFor) {
    cache.clear();
    pending.clear();
    cachedFor = files;
  }
  const key = `${cmd}|${JSON.stringify(args)}`;
  if (cache.has(key)) {
    return Promise.resolve(cache.get(key) as T);
  }
  let p = pending.get(key) as Promise<T> | undefined;
  if (!p) {
    p = invoke<T>(cmd, args).then((value) => {
      if (cachedFor === files) {
        cache.set(key, value);
      }
      pending.delete(key);
      return value;
    }, (e) => {
      pending.delete(key);
      throw e;
    });
    pending.set(key, p);
  }
  return p;
}// ask

// what the backend answers, or undefined until the first answer
export function useQuery<T>(cmd: string, args: Record<string, unknown> | null): T | undefined {
  const files = useScanStore((s) => s.files.map((f) => f.id).join(","));
  const key = args === null ? null : `${files}|${cmd}|${JSON.stringify(args)}`;
  const [answer, setAnswer] = useState<{ key: string; value: T } | null>(null);

  useEffect(() => {
    if (key === null || args === null) {
      return;
    }
    let live = true;
    ask<T>(cmd, args).then(
      (value) => live && setAnswer({ key, value }),
      (e) => console.error(`${cmd} failed`, e),
    );
    return () => {
      live = false;
    };
    // the key holds the arguments
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  if (key !== null && answer?.key !== key && files === cachedFor) {
    const known = cache.get(`${cmd}|${JSON.stringify(args)}`);
    if (known !== undefined) {
      return known as T;
    }
  }
  return args === null ? undefined : answer?.value;
}// useQuery

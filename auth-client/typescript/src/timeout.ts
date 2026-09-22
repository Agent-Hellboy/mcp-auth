export const DEFAULT_TIMEOUT_MS = 10_000;

export interface RequestTimeout {
  signal: AbortSignal | undefined;
  release: () => void;
}

/**
 * An abort signal for one outbound request, backed by a ref'd timer.
 *
 * AbortSignal.timeout is unref'd, so on an otherwise idle event loop the loop
 * drains before the timeout fires and a request that never settles hangs
 * instead of aborting. A ref'd timer fires deterministically; release() clears
 * it in a finally block so a completed request never holds the process open.
 */
export function requestTimeout(timeoutMs: number, signal?: AbortSignal): RequestTimeout {
  if (timeoutMs <= 0) return { signal, release: () => {} };
  const controller = new AbortController();
  const timer = setTimeout(
    () =>
      controller.abort(
        // Same shape AbortSignal.timeout and fetch produce, so a caller can
        // branch on error.name === "TimeoutError" whichever path aborted.
        new DOMException(`The operation was aborted due to timeout after ${timeoutMs}ms`, "TimeoutError"),
      ),
    timeoutMs,
  );
  const release = () => clearTimeout(timer);
  if (!signal) return { signal: controller.signal, release };
  return { signal: AbortSignal.any([signal, controller.signal]), release };
}

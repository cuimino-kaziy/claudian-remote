function requestBody(value) {
  if (value == null || typeof value === "string") return value;
  if (value instanceof ArrayBuffer) return value;
  if (ArrayBuffer.isView(value)) return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
  throw new TypeError("unsupported_request_body");
}

export function createObsidianFetch(requestUrl) {
  return async (url, options = {}) => {
    const signal = options.signal;
    if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new Error("request_aborted");
    const nativeRequest = Promise.resolve().then(() => {
      if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new Error("request_aborted");
      return requestUrl({
        url: String(url),
        method: options.method || "GET",
        headers: options.headers || {},
        body: requestBody(options.body),
        throw: false
      });
    });
    let response;
    if (signal?.addEventListener) {
      let abortListener;
      const aborted = new Promise((_, reject) => {
        abortListener = () => reject(signal.reason instanceof Error ? signal.reason : new Error("request_aborted"));
        signal.addEventListener("abort", abortListener, { once: true });
      });
      try { response = await Promise.race([nativeRequest, aborted]); }
      finally { signal.removeEventListener("abort", abortListener); }
    } else response = await nativeRequest;
    return {
      ok: response.status >= 200 && response.status < 300,
      status: response.status,
      headers: response.headers,
      async json() { return response.json; },
      async text() { return response.text; },
      async arrayBuffer() { return response.arrayBuffer; }
    };
  };
}

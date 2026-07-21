import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { resolveRuntimeAssets } from "./release-contract.mjs";

export const RUNTIME_ASSET_TIMEOUT_MS = 300_000;

function safeFinalUrl(value) {
  const parsed = new URL(value);
  return parsed.protocol === "https:"
    && !parsed.username
    && !parsed.password
    && !parsed.hash;
}

export async function verifyRuntimeAsset(
  target,
  component,
  {
    fetchImpl = fetch,
    timeoutMs = RUNTIME_ASSET_TIMEOUT_MS,
    output = process.stdout
  } = {}
) {
  const asset = target[component];
  const label = `${target.platform}/${target.arch} ${component}`;
  try {
    const response = await fetchImpl(asset.url, {
      redirect: "follow",
      signal: AbortSignal.timeout(timeoutMs)
    });
    if (!response.ok || !response.body) {
      throw new Error(`download failed: HTTP ${response.status}`);
    }
    if (!safeFinalUrl(response.url)) {
      throw new Error("redirected to an unsafe URL");
    }
    const digest = createHash("sha256");
    for await (const chunk of response.body) digest.update(chunk);
    const actual = digest.digest("hex");
    if (actual !== asset.sha256) throw new Error("digest mismatch");
    output.write(`${label} ${actual}: ok\n`);
    return actual;
  } catch (error) {
    throw new Error(`${label} verification failed: ${error.message}`, { cause: error });
  }
}

export async function verifyRuntimeAssets(
  runtime,
  options = {}
) {
  for (const target of resolveRuntimeAssets(runtime, {})) {
    for (const component of ["python", "uv"]) {
      await verifyRuntimeAsset(target, component, options);
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(import.meta.filename)) {
  const root = resolve(import.meta.dirname, "../..");
  const matrix = JSON.parse(readFileSync(join(root, "release/support-matrix.json"), "utf8"));
  await verifyRuntimeAssets(matrix.runtime);
}

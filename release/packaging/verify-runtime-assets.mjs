import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { resolveRuntimeAssets } from "./release-contract.mjs";

const root = resolve(import.meta.dirname, "../..");
const matrix = JSON.parse(readFileSync(join(root, "release/support-matrix.json"), "utf8"));
const targets = resolveRuntimeAssets(matrix.runtime, {});

for (const target of targets) {
  for (const component of ["python", "uv"]) {
    const asset = target[component];
    const response = await fetch(asset.url, { redirect: "follow" });
    if (!response.ok || !response.body) {
      throw new Error(`${target.platform}/${target.arch} ${component} download failed: HTTP ${response.status}`);
    }
    const finalUrl = new URL(response.url);
    if (finalUrl.protocol !== "https:" || finalUrl.username || finalUrl.password || finalUrl.hash) {
      throw new Error(`${target.platform}/${target.arch} ${component} redirected to an unsafe URL`);
    }
    const digest = createHash("sha256");
    for await (const chunk of response.body) digest.update(chunk);
    const actual = digest.digest("hex");
    if (actual !== asset.sha256) {
      throw new Error(`${target.platform}/${target.arch} ${component} digest mismatch`);
    }
    process.stdout.write(`${target.platform}/${target.arch} ${component} ${actual}: ok\n`);
  }
}

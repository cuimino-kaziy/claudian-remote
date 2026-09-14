export const REQUIRED_CLAUDIAN_VERSION = "2.2.6";
export const SUPPORTED_CLAUDIAN_VERSIONS = Object.freeze(["2.0.4", "2.2.6", "2.2.7"]);

export function usesNativeExecution(version) {
  return version === "2.2.6" || version === "2.2.7";
}

export function canSubmitToClaudian(claudian, tab) {
  const state = tab?.state;
  const admission = tab?.session?.acceptsIntents;
  return (usesNativeExecution(claudianManifest(claudian).version) ? admission === true : admission !== false)
    && !state?.isCreatingConversation && !state?.isSwitchingConversation && !state?.isRewinding;
}

export const REQUIRED_CLAUDIAN_CAPABILITIES = Object.freeze([
  "semantic_stream",
  "completion_barrier",
  "stop",
  "steer",
  "approval",
  "history_list",
  "history_select"
]);

export const COMPATIBILITY_SET = Object.freeze({
  id: "claudian-remote-0.2.0",
  plugin: "0.2.0",
  companion: "0.2.0",
  relay: "0.2.0",
  protocol: "claudian.remote.v2",
  configuration_schema: 1
});

function text(value) {
  return typeof value === "string" ? value.trim() : "";
}

export function claudianManifest(claudian) {
  const manifest = claudian?.manifest || claudian?.plugin?.manifest || {};
  return {
    id: text(manifest.id || claudian?.id),
    version: text(manifest.version || claudian?.version)
  };
}

export function evaluateClaudianCompatibility({ manifest = {}, capabilities = {} } = {}) {
  const currentVersion = text(manifest.version);
  if (!SUPPORTED_CLAUDIAN_VERSIONS.includes(currentVersion)) {
    return {
      writable: false,
      mode: "read_only",
      reason: "unsupported_claudian_version",
      current_version: currentVersion || "unknown",
      required_version: REQUIRED_CLAUDIAN_VERSION,
      missing_capabilities: [],
      remediation: `Update Claudian to ${REQUIRED_CLAUDIAN_VERSION}`
    };
  }
  // Native execution terminal events bypass stream chunks; steer is provider-dependent.
  const required = usesNativeExecution(currentVersion)
    ? REQUIRED_CLAUDIAN_CAPABILITIES.map((key) => key === "steer" ? "native_execution_events" : key)
    : REQUIRED_CLAUDIAN_CAPABILITIES;
  const missing = required.filter((key) => capabilities?.[key] !== true);
  if (missing.length) {
    return {
      writable: false,
      mode: "read_only",
      reason: "required_capability_missing",
      current_version: currentVersion,
      required_version: REQUIRED_CLAUDIAN_VERSION,
      missing_capabilities: missing,
      remediation: `Restore required Claudian capabilities: ${missing.join(", ")}`
    };
  }
  return {
    writable: true,
    mode: "streaming",
    reason: "ready",
    current_version: currentVersion,
    required_version: REQUIRED_CLAUDIAN_VERSION,
    missing_capabilities: [],
    remediation: null
  };
}

export function evaluateCompatibilitySet(actual = {}, required = COMPATIBILITY_SET) {
  const source = actual && typeof actual === "object" ? actual : {};
  const mismatches = [];
  for (const component of ["id", "plugin", "companion", "relay", "protocol", "configuration_schema"]) {
    if (source[component] !== required[component]) {
      mismatches.push({ component, current: source[component] ?? null, required: required[component] });
    }
  }
  if (mismatches.length) {
    return {
      writable: false,
      mode: "read_only",
      reason: "compatibility_set_mismatch",
      mismatches,
      actual: { ...source },
      required: { ...required },
      remediation: "Update Claudian Remote components to one compatible release set"
    };
  }
  return {
    writable: true,
    mode: "streaming",
    reason: "ready",
    mismatches: [],
    actual: { ...source },
    required: { ...required },
    remediation: null
  };
}

export function normalizeCompatibilityResult(value) {
  if (value && typeof value === "object" && typeof value.writable === "boolean") {
    return {
      writable: value.writable,
      mode: value.writable ? "streaming" : "read_only",
      reason: text(value.reason) || (value.writable ? "ready" : "compatibility_set_mismatch"),
      mismatches: Array.isArray(value.mismatches) ? value.mismatches.map((item) => ({ ...item })) : [],
      actual: value.actual && typeof value.actual === "object" ? { ...value.actual } : null,
      required: value.required && typeof value.required === "object" ? { ...value.required } : { ...COMPATIBILITY_SET },
      remediation: text(value.remediation) || null
    };
  }
  return evaluateCompatibilitySet(value);
}

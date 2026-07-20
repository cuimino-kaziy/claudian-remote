export class RenderGeneration {
  constructor() { this.value = 0; }
  next() { this.value += 1; return this.value; }
  isCurrent(generation) { return generation === this.value; }
  invalidate() { this.value += 1; }
}

export function renderDelay({ final = false, elapsedMs = Infinity, throttleMs = 250 } = {}) {
  return final ? 0 : Math.max(0, throttleMs - elapsedMs);
}

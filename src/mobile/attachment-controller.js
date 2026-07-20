import { IncrementalSha256, sha256Hex } from "./sha256-stream.js";

const CHUNK_BYTES = 1024 * 1024;

function sameSession(a, b) {
  return a?.mac_session_id === b?.mac_session_id && a?.mac_connection_generation === b?.mac_connection_generation;
}

function abortError(signal, fallback = "upload_cancelled") {
  return signal?.reason instanceof Error ? signal.reason : new Error(fallback);
}

export class AttachmentController {
  constructor({ baseUrl, tokenProvider, getSession, fetchImpl = globalThis.fetch, onChange = () => {}, chunkBytes = CHUNK_BYTES }) {
    this.baseUrl = String(baseUrl || "").replace(/\/+$/, "");
    this.tokenProvider = tokenProvider;
    this.getSession = getSession;
    this.fetchImpl = fetchImpl;
    this.onChange = onChange;
    this.chunkBytes = Math.min(CHUNK_BYTES, Math.max(64 * 1024, chunkBytes));
    this.current = null;
  }

  headers(extra = {}) {
    const token = this.tokenProvider?.();
    if (!token) throw new Error("mobile_token_missing");
    return { Authorization: `Bearer ${token}`, ...extra };
  }

  snapshot() {
    return this.current ? [{
      uploadId: this.current.uploadId,
      name: this.current.name,
      size: this.current.size,
      status: this.current.status,
      progress: this.current.size ? this.current.offset / this.current.size : 1,
      vaultPath: this.current.vaultPath || null,
      error: this.current.error || null,
      reserved: Boolean(this.current.reservationDeliveryId)
    }] : [];
  }

  changed() { this.onChange(this.snapshot()); }

  throwIfAborted(signal) {
    if (signal?.aborted) throw abortError(signal);
  }

  assertActive(item) {
    this.throwIfAborted(item?.abortController?.signal);
    if (!item || item !== this.current) throw new Error("upload_cancelled");
  }

  async hashFile(file, signal) {
    const hash = new IncrementalSha256();
    for (let offset = 0; offset < file.size; offset += this.chunkBytes) {
      this.throwIfAborted(signal);
      const buffer = await file.slice(offset, Math.min(file.size, offset + this.chunkBytes)).arrayBuffer();
      this.throwIfAborted(signal);
      const bytes = new Uint8Array(buffer);
      hash.update(bytes);
    }
    this.throwIfAborted(signal);
    return hash.digestHex();
  }

  session() {
    const value = this.getSession?.();
    if (!value?.mac_session_id || !value?.mac_connection_generation) throw new Error("mac_offline");
    return value;
  }

  async upload(file) {
    if (this.current && !["failed", "cancelled"].includes(this.current.status)) throw new Error("one_upload_at_a_time");
    const session = this.session();
    const item = {
      file,
      name: file.name || "attachment.bin",
      size: file.size,
      status: "hashing",
      offset: 0,
      index: 0,
      session,
      abortController: new AbortController()
    };
    this.current = item;
    this.changed();
    try {
      item.totalSha256 = await this.hashFile(file, item.abortController.signal);
      this.assertActive(item);
      if (!sameSession(session, this.session())) throw new Error("session_changed");
      item.status = "starting";
      this.changed();
      const response = await this.fetchImpl(`${this.baseUrl}/api/v2/uploads`, {
        method: "POST",
        headers: this.headers({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          display_name: item.name,
          content_type: file.type || "application/octet-stream",
          total_bytes: file.size,
          sha256: item.totalSha256,
          mac_session_id: session.mac_session_id,
          mac_connection_generation: session.mac_connection_generation
        }),
        signal: item.abortController.signal
      });
      const body = await response.json();
      this.assertActive(item);
      if (!response.ok) throw new Error(body.error || `upload_begin_${response.status}`);
      item.uploadId = body.upload_id;
      item.offset = Number(body.next_offset ?? body.received_bytes) || 0;
      item.index = Number(body.next_index) || 0;
      await this.uploadRemaining(item);
      this.assertActive(item);
      return this.snapshot()[0];
    } catch (error) {
      if (this.current === item && !item.abortController.signal.aborted) {
        item.status = sameSession(session, this.getSession?.()) && item.uploadId ? "paused" : "failed";
        item.error = error?.message || "upload_failed";
        this.changed();
      }
      throw error;
    }
  }

  async uploadRemaining(item = this.current) {
    this.assertActive(item);
    item.status = "uploading";
    this.changed();
    while (item.offset < item.size) {
      this.assertActive(item);
      if (!sameSession(item.session, this.session())) throw new Error("session_changed");
      const end = Math.min(item.size, item.offset + this.chunkBytes);
      const buffer = await item.file.slice(item.offset, end).arrayBuffer();
      this.assertActive(item);
      const bytes = new Uint8Array(buffer);
      const response = await this.fetchImpl(`${this.baseUrl}/api/v2/uploads/${item.uploadId}/chunks/${item.index}`, {
        method: "PUT",
        headers: this.headers({
          "Content-Type": "application/octet-stream",
          "X-Upload-Offset": String(item.offset),
          "X-Chunk-SHA256": sha256Hex(bytes),
          "X-Mac-Session-ID": item.session.mac_session_id,
          "X-Mac-Connection-Generation": String(item.session.mac_connection_generation)
        }),
        body: bytes,
        signal: item.abortController.signal
      });
      const body = await response.json();
      this.assertActive(item);
      if (!response.ok) throw new Error(body.error || `upload_chunk_${response.status}`);
      item.offset = Number(body.next_offset ?? body.received_bytes);
      item.index = Number(body.next_index);
      this.changed();
    }
    item.status = "finalizing";
    this.changed();
    const response = await this.fetchImpl(`${this.baseUrl}/api/v2/uploads/${item.uploadId}/finalize`, {
      method: "POST",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({ ...item.session, sha256: item.totalSha256 }),
      signal: item.abortController.signal
    });
    const body = await response.json();
    this.assertActive(item);
    if (!response.ok) throw new Error(body.error || `upload_finalize_${response.status}`);
    item.status = "importing";
    this.changed();
  }

  async resume() {
    if (!this.current || this.current.status !== "paused") throw new Error("upload_not_paused");
    if (!sameSession(this.current.session, this.session())) throw new Error("session_changed");
    const item = this.current;
    item.abortController = new AbortController();
    await this.uploadRemaining(item);
    return this.snapshot()[0];
  }

  onArtifact(artifact) {
    if (!this.current || artifact?.artifact_id !== this.current.uploadId) return false;
    if (this.current.status === "ready" && this.current.vaultPath === artifact.vault_path) return true;
    this.current.status = "ready";
    this.current.vaultPath = artifact.vault_path;
    this.current.kind = artifact.kind;
    this.changed();
    return true;
  }

  references() {
    if (this.current?.status !== "ready" || !this.current.vaultPath) return [];
    return [{ upload_id: this.current.uploadId, vault_path: this.current.vaultPath, label: this.current.name }];
  }

  reserveReady(deliveryId) {
    const normalizedDeliveryId = String(deliveryId || "");
    const refs = this.references();
    if (!normalizedDeliveryId || !refs.length || this.current.reservationDeliveryId) return [];
    this.current.reservationDeliveryId = normalizedDeliveryId;
    this.changed();
    return refs;
  }

  releaseReservation(deliveryId) {
    const normalizedDeliveryId = String(deliveryId || "");
    if (!this.current || this.current.reservationDeliveryId !== normalizedDeliveryId) return false;
    delete this.current.reservationDeliveryId;
    this.changed();
    return true;
  }

  consumeReservation(deliveryId) {
    const normalizedDeliveryId = String(deliveryId || "");
    if (!this.current || this.current.reservationDeliveryId !== normalizedDeliveryId) return [];
    const refs = this.references();
    if (!refs.length) return [];
    this.current = null;
    this.changed();
    return refs;
  }

  invalidateSession(currentSession) {
    if (!this.current || ["ready", "failed", "cancelled"].includes(this.current.status)) return false;
    if (sameSession(this.current.session, currentSession)) return false;
    this.current.abortController?.abort(new Error("session_changed"));
    this.current.status = "failed";
    this.current.error = "session_changed";
    this.changed();
    return true;
  }

  consumeReady() {
    if (this.current?.reservationDeliveryId) return [];
    const refs = this.references();
    if (refs.length) { this.current = null; this.changed(); }
    return refs;
  }

  async cancel() {
    const item = this.current;
    if (!item) return;
    item.abortController?.abort(new Error("upload_cancelled"));
    if (this.current === item) this.current = null;
    this.changed();
    if (!item.uploadId || item.status === "ready") return;
    try {
      await this.fetchImpl(`${this.baseUrl}/api/v2/uploads/${item.uploadId}`, {
        method: "DELETE",
        headers: this.headers({
          "X-Mac-Session-ID": item.session.mac_session_id,
          "X-Mac-Connection-Generation": String(item.session.mac_connection_generation)
        })
      });
    } catch { /* TTL cleanup remains the final safety net. */ }
  }

  async dispose() { await this.cancel(); }
}

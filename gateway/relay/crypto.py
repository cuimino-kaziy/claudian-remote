#!/usr/bin/env python3
"""Small payload-encryption helpers for the private Claudian relay V0."""

import base64
import hashlib
import hmac
import json
import re
import secrets
from typing import Any, Dict


ALG = "pbkdf2-hmac-sha256+xor-hmac-v1"


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _derive_key(secret: str, pairing_id: str, purpose: bytes) -> bytes:
    salt = b"claudian-remote-relay:" + pairing_id.encode("utf-8") + b":" + purpose
    return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 120_000, dklen=32)


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    chunks = []
    counter = 0
    while sum(len(chunk) for chunk in chunks) < length:
        counter_bytes = counter.to_bytes(8, "big")
        chunks.append(hmac.new(key, nonce + counter_bytes, hashlib.sha256).digest())
        counter += 1
    return b"".join(chunks)[:length]


class PayloadCrypto:
    """Encrypt JSON payloads with a shared pairing secret.

    This keeps queued relay bodies out of plaintext without adding runtime
    dependencies to the VPS. Before public distribution, replace or audit this
    V0 construction with a standard AEAD implementation.
    """

    def __init__(self, secret: str, pairing_id: str):
        if not secret:
            raise ValueError("payload secret is required")
        if not pairing_id:
            raise ValueError("pairing_id is required")
        self.pairing_id = pairing_id
        self._enc_key = _derive_key(secret, pairing_id, b"encrypt")
        self._auth_key = _derive_key(secret, pairing_id, b"authenticate")

    def encrypt_json(self, payload: Dict[str, Any]) -> Dict[str, str]:
        plaintext = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        nonce = secrets.token_bytes(24)
        cipher_bytes = bytes(a ^ b for a, b in zip(plaintext, _keystream(self._enc_key, nonce, len(plaintext))))
        aad = f"{ALG}:{self.pairing_id}:".encode("utf-8") + nonce
        tag = hmac.new(self._auth_key, aad + cipher_bytes, hashlib.sha256).digest()
        return {
            "alg": ALG,
            "pairing_id": self.pairing_id,
            "nonce": _b64encode(nonce),
            "ciphertext": _b64encode(cipher_bytes),
            "tag": _b64encode(tag),
        }

    def decrypt_json(self, envelope: Dict[str, str]) -> Dict[str, Any]:
        if envelope.get("alg") != ALG:
            raise ValueError("unsupported payload encryption algorithm")
        if envelope.get("pairing_id") != self.pairing_id:
            raise ValueError("payload pairing mismatch")
        nonce = _b64decode(envelope["nonce"])
        cipher_bytes = _b64decode(envelope["ciphertext"])
        tag = _b64decode(envelope["tag"])
        aad = f"{ALG}:{self.pairing_id}:".encode("utf-8") + nonce
        expected = hmac.new(self._auth_key, aad + cipher_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("payload authentication failed")
        plaintext = bytes(a ^ b for a, b in zip(cipher_bytes, _keystream(self._enc_key, nonce, len(cipher_bytes))))
        value = json.loads(plaintext.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("payload must decode to a JSON object")
        return value


_BEARER_RE = re.compile(r"\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_TOKEN_FIELD_RE = re.compile(r'("(?:token|secret|authorization|bearer|api_key)"\s*:\s*")([^"]+)(")', re.IGNORECASE)
_MAC_PATH_RE = re.compile(r"/Users/[^\\s\"']+")


def redact_text(value: str) -> str:
    """Remove secrets and local paths from logs or diagnostics."""

    redacted = _BEARER_RE.sub(r"\1[REDACTED]", value)
    redacted = _TOKEN_FIELD_RE.sub(r"\1[REDACTED]\3", redacted)
    redacted = _MAC_PATH_RE.sub("[REDACTED_PATH]", redacted)
    return redacted

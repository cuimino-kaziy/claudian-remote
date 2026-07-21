"""Shared private-state IO and ownership digest helpers."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Mapping

from .checkpoint import PrivateStateDirectory


def write_private_json(
    path: Path,
    value: Mapping[str, Any],
    *,
    validate_secret_free: bool = True,
) -> None:
    """Atomically persist secret-free lifecycle state with private modes."""

    target = Path(path)
    PrivateStateDirectory(target.parent).atomic_write_json(
        target,
        value,
        validate_secret_free=validate_secret_free,
    )


def _update_file_digest(digest: Any, path: Path) -> None:
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)


def tree_digest(path: Path) -> str:
    """Hash one owned resource without loading whole files into memory."""

    target = Path(path)
    digest = hashlib.sha256()
    if target.is_symlink():
        digest.update(os.readlink(target).encode())
        return digest.hexdigest()
    if target.is_file():
        _update_file_digest(digest, target)
        return digest.hexdigest()
    for item in sorted(target.rglob("*"), key=lambda value: str(value.relative_to(target))):
        relative = str(item.relative_to(target))
        digest.update(relative.encode())
        if item.is_file() and not item.is_symlink():
            _update_file_digest(digest, item)
    return digest.hexdigest()

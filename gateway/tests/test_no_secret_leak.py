from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
IGNORED_PARTS = {".git", ".venv", "venv", "node_modules", "dist", "__pycache__", ".pytest_cache"}
FORBIDDEN_NAMES = {
    ".token",
    "config.local.json",
    "companion_state.json",
    "companion_state_v2.json",
    "scheduled_tasks.json",
}


def public_files():
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in IGNORED_PARTS for part in path.parts):
            continue
        yield path


def test_curated_tree_excludes_local_state_and_secret_files():
    forbidden_suffixes = (".db", ".sqlite", ".sqlite3", ".log", ".wal", ".shm")
    for path in public_files():
        assert path.name not in FORBIDDEN_NAMES, path
        assert not path.name.endswith(forbidden_suffixes), path


def test_curated_tree_has_no_author_path_domain_or_credential():
    author_path = "/".join(("", "Users", "lan" + "tian"))
    author_domain = "209-54-104-142" + ".sslip.io"
    credential_patterns = (
        re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    )
    for path in public_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        assert author_path not in text, path
        assert author_domain not in text, path
        for pattern in credential_patterns:
            assert pattern.search(text) is None, path


def test_only_final_plugin_identity_can_be_installed():
    manifest = (ROOT / "manifest.json").read_text(encoding="utf-8")
    matrix = (ROOT / "release" / "support-matrix.json").read_text(encoding="utf-8")
    assert '"id": "claudian-remote"' in manifest
    assert '"migration_source_ids": ["whale-agent-bridge"]' in matrix
    assert '"legacy_id_may_coexist": false' in matrix

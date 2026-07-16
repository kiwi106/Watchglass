"""Safe local file discovery."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

IGNORED_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "vendor",
    "venv",
}
MAX_FILE_SIZE = 1_000_000


@dataclass(frozen=True, slots=True)
class ScannedFile:
    path: Path
    relative_path: Path
    text: str


def discover_files(root: Path) -> list[ScannedFile]:
    """Read eligible text files without following directory symlinks."""
    files: list[ScannedFile] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in IGNORED_DIRS for part in relative.parts):
            continue
        if not path.is_file() or path.is_symlink():
            continue
        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                continue
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        files.append(ScannedFile(path, relative, text))
    return files

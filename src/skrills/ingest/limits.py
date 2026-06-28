"""Centralized ingest safety limits, env-tunable."""
from __future__ import annotations

import os

MAX_UPLOAD_MB = int(os.environ.get("SKRILLS_MAX_UPLOAD_MB", "50"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024

MAX_FILE_COUNT = int(os.environ.get("SKRILLS_MAX_FILE_COUNT", "5000"))

# Zip bomb guard: uncompressed-to-compressed ratio
MAX_ZIP_RATIO = float(os.environ.get("SKRILLS_MAX_ZIP_RATIO", "100"))
# Hard cap on extracted size, regardless of ratio
MAX_EXTRACTED_BYTES = int(os.environ.get("SKRILLS_MAX_EXTRACTED_MB", "200")) * 1024 * 1024

GIT_CLONE_TIMEOUT = int(os.environ.get("SKRILLS_GIT_CLONE_TIMEOUT", "60"))

GIT_HOST_ALLOWLIST = {
    h.strip().lower()
    for h in os.environ.get(
        "SKRILLS_GIT_HOST_ALLOWLIST", "github.com,gitlab.com,bitbucket.org"
    ).split(",")
    if h.strip()
}

# Files we'll show in the content viewer / scan with text-based scanners
TEXT_EXTS = {
    ".md", ".markdown", ".txt", ".rst",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".go", ".rs", ".java", ".cs",
    ".sh", ".bash", ".ps1", ".bat",
    ".html", ".css", ".sql",
    ".prompt", ".skill",
}

# Skill-like filenames — get the expensive scanners
SKILL_FILENAMES = {
    "skill.md", "system.md", "prompt.md", "system_prompt.md",
    "agent.md", "instructions.md", "claude.md", "copilot.md",
    "agent.json", "skill.json", "agent.yaml", "skill.yaml",
}


def is_text_file(name: str) -> bool:
    name_lower = name.lower()
    if name_lower in SKILL_FILENAMES:
        return True
    for ext in TEXT_EXTS:
        if name_lower.endswith(ext):
            return True
    return False


def is_skill_file(name: str) -> bool:
    name_lower = name.rsplit("/", 1)[-1].lower()
    return name_lower in SKILL_FILENAMES

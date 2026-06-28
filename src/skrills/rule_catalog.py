"""Single source of truth for the heuristic rule packs.

Both the heuristics scanner and the web UI (results popovers + /glossary page)
read rule metadata from here so rule definitions live in exactly one place.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

RULES_DIR = Path(__file__).resolve().parent / "rules"
RULE_FILES = ("injection.yaml", "tool_risks.yaml")

# Stable display order + human labels for grouping in the glossary.
CATEGORY_LABELS: dict[str, str] = {
    "injection": "Prompt injection",
    "indirect_injection": "Indirect injection",
    "tool_poisoning": "Tool poisoning",
    "excessive_agency": "Excessive agency",
    "secret": "Secret leakage",
    "other": "Other",
}

_catalog: dict[str, dict[str, Any]] | None = None


def load_catalog() -> dict[str, dict[str, Any]]:
    """Return all heuristic rules keyed by rule id, in file/definition order.

    Parsed once and cached. Each value is the raw YAML rule dict (id, title,
    severity, category, pattern, description, remediation, false_positives).
    """
    global _catalog
    if _catalog is None:
        catalog: dict[str, dict[str, Any]] = {}
        for fname in RULE_FILES:
            p = RULES_DIR / fname
            if not p.exists():
                continue
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            for rule in data.get("rules", []):
                rid = rule.get("id")
                if rid:
                    catalog[rid] = rule
        _catalog = catalog
    return _catalog


def group_by_category(
    catalog: dict[str, dict[str, Any]] | None = None,
) -> list[tuple[str, str, list[dict[str, Any]]]]:
    """Group rules for the glossary as (category_key, label, rules) tuples,
    ordered by CATEGORY_LABELS."""
    cat = catalog if catalog is not None else load_catalog()
    grouped: dict[str, list[dict[str, Any]]] = {}
    for rule in cat.values():
        grouped.setdefault(rule.get("category", "other"), []).append(rule)
    out: list[tuple[str, str, list[dict[str, Any]]]] = []
    for key, label in CATEGORY_LABELS.items():
        if key in grouped:
            out.append((key, label, grouped[key]))
    # Any categories not in CATEGORY_LABELS (defensive) appended last.
    for key, rules in grouped.items():
        if key not in CATEGORY_LABELS:
            out.append((key, key.replace("_", " ").title(), rules))
    return out

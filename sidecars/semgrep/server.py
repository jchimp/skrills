"""Tiny HTTP wrapper around `semgrep scan` so Skrills can call it over the network.

POST /scan
  body: { "path": "/shared/<scan_id>" }   (path must be a mounted volume the sidecar can read)
  resp: { "findings": [ ... ] }           (raw semgrep JSON results array)

GET /healthz -> { "status": "ok" }

For Skrills v2 the main app instead POSTs a tarball:
  POST /scan-tar  (multipart: file=<tar.gz of repo>)
This avoids any need for a shared volume between containers.
"""
from __future__ import annotations

import json
import subprocess
import tarfile
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile

app = FastAPI(title="skrills-semgrep")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/scan-tar")
async def scan_tar(file: UploadFile = File(...)):
    with tempfile.TemporaryDirectory() as td:
        tar_path = Path(td) / "repo.tar.gz"
        data = await file.read()
        tar_path.write_bytes(data)

        repo_dir = Path(td) / "repo"
        repo_dir.mkdir()
        try:
            with tarfile.open(tar_path, "r:gz") as tf:
                _safe_extract(tf, repo_dir)
        except (tarfile.TarError, ValueError) as e:
            raise HTTPException(400, f"bad tarball: {e}")

        try:
            proc = subprocess.run(
                [
                    "semgrep", "scan",
                    "--config", "p/owasp-top-ten",
                    "--config", "p/security-audit",
                    "--config", "p/secrets",
                    "--json",
                    "--quiet",
                    "--timeout", "30",
                    "--metrics", "off",
                    str(repo_dir),
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(504, "semgrep scan timed out")

        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            raise HTTPException(500, f"semgrep returned non-JSON: {proc.stderr[:500]}")

        results = data.get("results", [])
        out = []
        for r in results:
            extra = r.get("extra", {})
            sev_raw = (extra.get("severity") or "INFO").upper()
            sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(sev_raw, "low")
            out.append({
                "rule_id": r.get("check_id", "semgrep.rule"),
                "title": extra.get("message", "Semgrep finding")[:200],
                "severity": sev,
                "category": "code_security",
                "description": extra.get("message", ""),
                "file_path": _relpath(r.get("path", ""), str(repo_dir)),
                "line": (r.get("start") or {}).get("line"),
                "evidence": (extra.get("lines") or "")[:240],
                "remediation": (extra.get("metadata") or {}).get("fix") or None,
            })
        return {"findings": out, "count": len(out)}


def _safe_extract(tf: tarfile.TarFile, dest: Path) -> None:
    """Reject path traversal in tar entries."""
    dest = dest.resolve()
    for m in tf.getmembers():
        target = (dest / m.name).resolve()
        if not str(target).startswith(str(dest)):
            raise ValueError(f"path traversal: {m.name}")
    tf.extractall(dest)


def _relpath(p: str, root: str) -> str:
    try:
        return str(Path(p).resolve().relative_to(Path(root).resolve()))
    except (ValueError, OSError):
        return p

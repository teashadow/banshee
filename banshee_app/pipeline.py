"""Recon pipeline implementation."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import requests

from .config import get_secret
from .config import RECON_ROOT
from .storage import latest_run_dir, now_slug, read_json, target_dir, write_json

SAFE_TEMPLATE_DIRS = [
    str(Path.home() / "nuclei-templates" / "http" / "technologies"),
    str(Path.home() / "nuclei-templates" / "http" / "exposures"),
]
MAX_SUBDOMAINS_DEFAULT = 400
MAX_SUBDOMAINS_QUICK = 120

# Путь к CLI periscope для гейта scope. Инструменты семьи связаны через КОНТРАКТ (вызов + rc),
# не импортом: periscope check <target> <program> → rc 0 in-scope · 1 out-of-scope · 2 unknown.
# parents[2] = каталог mad-tools (pipeline.py лежит в mad-tools/banshee/banshee_app/)
PERISCOPE_CLI = str(Path(__file__).resolve().parents[2] / "periscope" / ".venv" / "bin" / "python")
PERISCOPE_DIR = str(Path(__file__).resolve().parents[2] / "periscope")


class ScopeBlocked(RuntimeError):
    """Цель не авторизована к сканированию — recon НЕ запускается."""


def scope_gate(target: str, program: str | None) -> dict[str, Any]:
    """🔴🔴 Авторизационный гейт ПЕРЕД сканом. Fail-safe: неизвестно/нет program = ЗАПРЕТ.

    Recon без явной программы и без in-scope-подтверждения — несанкционированное сканирование.
    Гейт вызывает periscope через контракт (CLI + rc). Молчание = запрет.
    """
    if not program:
        raise ScopeBlocked("не задана scope-программа (--program) — по умолчанию НЕ сканирую (fail-safe)")
    try:
        proc = subprocess.run([PERISCOPE_CLI, "-m", "periscope_app.cli", "check", target, program],
                              cwd=PERISCOPE_DIR, capture_output=True, text=True, timeout=30)
    except Exception as e:
        raise ScopeBlocked(f"гейт scope не отработал ({e}) — по умолчанию НЕ сканирую (fail-safe)")
    if proc.returncode == 0:
        return {"gate": "in-scope", "program": program, "почему": "цель авторизована periscope"}
    if proc.returncode == 1:
        raise ScopeBlocked(f"{target} ВНЕ scope программы {program} — сканирование запрещено")
    raise ScopeBlocked(f"scope для {target}/{program} неизвестен — НЕ сканирую (fail-safe, rc={proc.returncode})")


def _run(
    cmd: list[str],
    *,
    output_path: Path | None = None,
    timeout: int = 180,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False, timeout=timeout)
    if output_path is not None:
        output_path.write_text(proc.stdout, encoding="utf-8")
    return proc


def _require_binary(name: str) -> str:
    markers = {
        "subfinder": "subdomain discovery tool",
        "httpx": "-list string",
        "nuclei": "template based vulnerability scanner",
    }
    candidates = []
    primary = shutil.which(name)
    if primary:
        candidates.append(primary)
    candidates.extend(
        str(path)
        for path in [
            Path.home() / ".local" / "bin" / name,
            Path.home() / "go" / "bin" / name,
            Path("/usr/local/bin") / name,
        ]
        if path.exists()
    )
    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            proc = subprocess.run([candidate, "--help"], text=True, capture_output=True, check=False, timeout=10)
        except Exception:
            continue
        help_text = (proc.stdout + proc.stderr).lower()
        if markers.get(name, "") in help_text:
            return candidate
    raise RuntimeError(f"required binary not found or unexpected variant: {name}")


def _extract_ips(live_hosts_lines: list[str]) -> list[str]:
    ips: list[str] = []
    for line in live_hosts_lines:
        match = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", line)
        if match:
            ips.append(match.group(1))
    return sorted(set(ips))


def _trim_subdomains(path: Path, *, quick: bool) -> list[str]:
    lines = []
    seen = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line in seen:
            continue
        seen.add(line)
        lines.append(line)
    cap = MAX_SUBDOMAINS_QUICK if quick else MAX_SUBDOMAINS_DEFAULT
    trimmed = lines[:cap]
    path.write_text("\n".join(trimmed) + ("\n" if trimmed else ""), encoding="utf-8")
    return trimmed


def _shodan_host(ip: str) -> dict[str, Any]:
    key = get_secret("SHODAN_API_KEY")
    if not key:
        return {"ip": ip, "ok": False, "error": "missing SHODAN_API_KEY"}
    resp = requests.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": key}, timeout=30)
    if resp.status_code != 200:
        return {"ip": ip, "ok": False, "error": f"shodan_http_{resp.status_code}", "details": resp.text[:400]}
    data = resp.json()
    return {
        "ip": ip,
        "ok": True,
        "ports": data.get("ports", []),
        "hostnames": data.get("hostnames", []),
        "org": data.get("org"),
        "os": data.get("os"),
        "vulns": sorted((data.get("vulns") or {}).keys()) if isinstance(data.get("vulns"), dict) else data.get("vulns", []),
        "services": [
            {
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "data": (item.get("data") or "")[:400],
            }
            for item in data.get("data", [])[:20]
        ],
    }


def shodan_search(query: str) -> dict[str, Any]:
    key = get_secret("SHODAN_API_KEY")
    if not key:
        raise RuntimeError("missing SHODAN_API_KEY in ~/.config/mad/secrets.env")
    resp = requests.get("https://api.shodan.io/shodan/host/search", params={"key": key, "query": query}, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return {
        "query": query,
        "total": data.get("total", 0),
        "matches": [
            {
                "ip_str": item.get("ip_str"),
                "port": item.get("port"),
                "hostnames": item.get("hostnames", []),
                "org": item.get("org"),
                "product": item.get("product"),
                "data": (item.get("data") or "")[:240],
            }
            for item in data.get("matches", [])[:10]
        ],
    }


def shodan_host(ip: str) -> dict[str, Any]:
    result = _shodan_host(ip)
    if not result.get("ok"):
        raise RuntimeError(str(result.get("error")))
    return result


def _heuristic_summary(target: str, live_hosts: list[str], shodan_data: list[dict[str, Any]], nuclei_lines: list[str]) -> str:
    findings: list[str] = []
    if live_hosts:
        findings.append(f"1. Live hosts discovered: {len(live_hosts)} hosts responded after subdomain enumeration.")
    risky = [item for item in shodan_data if item.get("ports") and any(port not in {80, 443} for port in item["ports"])]
    if risky:
        sample = risky[0]
        findings.append(f"2. Non-standard ports are exposed on {sample['ip']}: {', '.join(str(p) for p in sample['ports'][:8])}.")
    vuln_hosts = [item for item in shodan_data if item.get("vulns")]
    if vuln_hosts:
        sample = vuln_hosts[0]
        findings.append(f"3. Shodan reports CVE-linked exposure on {sample['ip']}: {', '.join(sample['vulns'][:5])}.")
    if nuclei_lines:
        findings.append(f"4. nuclei safe templates produced {len(nuclei_lines)} findings worth manual review.")
    tech_lines = [line for line in live_hosts if "[" in line and "]" in line]
    if tech_lines:
        findings.append("5. httpx surfaced technology fingerprints and titles; inspect live_hosts.txt for stack-specific entry points.")
    if not findings:
        findings.append(f"1. Recon completed for {target}, but no standout findings were auto-ranked. Review raw artifacts.")
    while len(findings) < 5:
        findings.append(f"{len(findings) + 1}. Additional manual triage recommended for target surface expansion and scope validation.")
    header = f"# Banshee Summary — {target}\n\nGenerated by local heuristic fallback.\n"
    return header + "\n".join(findings) + "\n"


def summarize_run(target: str, live_hosts: list[str], shodan_data: list[dict[str, Any]], nuclei_lines: list[str]) -> str:
    ask_ai = shutil.which("ask-ai") or str(Path.home() / ".local" / "bin" / "ask-ai")
    if ask_ai and Path(ask_ai).exists():
        prompt = (
            f"Вот результаты recon по {target}. Выдели топ-5 интересных находок для bug bounty. "
            "Фокус: нестандартные порты, exposed tech, потенциальные attack surfaces. "
            "Формат: markdown, пронумерованный список с кратким обоснованием.\n\n"
            f"live_hosts={json.dumps(live_hosts[:50], ensure_ascii=False)}\n"
            f"shodan={json.dumps(shodan_data[:20], ensure_ascii=False)}\n"
            f"nuclei={json.dumps(nuclei_lines[:100], ensure_ascii=False)}\n"
        )
        try:
            proc = subprocess.run([ask_ai, prompt], text=True, capture_output=True, check=False, timeout=120)
            text = (proc.stdout or "").strip()
            if proc.returncode == 0 and text:
                return f"# Banshee Summary — {target}\n\nGenerated via ask-ai.\n\n{text}\n"
        except Exception:
            pass
    return _heuristic_summary(target, live_hosts, shodan_data, nuclei_lines)


def run_target(target: str, *, quick: bool = False, program: str | None = None) -> Path:
    # 🔴🔴 Гейт авторизации ПЕРЕД любым внешним вызовом. Вне scope → ScopeBlocked, скан не идёт.
    scope_gate(target, program)
    subfinder_bin = _require_binary("subfinder")
    httpx_bin = _require_binary("httpx")
    if not quick:
        nuclei_bin = _require_binary("nuclei")
    else:
        nuclei_bin = None

    stamp = now_slug()
    run_dir = target_dir(target, stamp)
    raw_subs = run_dir / "raw_subs.txt"
    live_hosts_file = run_dir / "live_hosts.txt"
    shodan_json = run_dir / "shodan_enriched.json"
    nuclei_file = run_dir / "nuclei_findings.txt"
    summary_file = run_dir / "summary.md"
    meta_file = run_dir / "run.json"

    subfinder = _run([subfinder_bin, "-d", target, "-silent"], output_path=raw_subs, timeout=120)
    if subfinder.returncode != 0:
        raise RuntimeError(subfinder.stderr.strip() or "subfinder failed")
    trimmed_subs = _trim_subdomains(raw_subs, quick=quick)

    httpx = _run(
        [
            httpx_bin,
            "-l",
            str(raw_subs),
            "-silent",
            "-title",
            "-tech-detect",
            "-status-code",
            "-threads",
            "50",
            "-timeout",
            "5",
            "-retries",
            "1",
        ],
        output_path=live_hosts_file,
        timeout=180 if quick else 300,
    )
    if httpx.returncode != 0:
        raise RuntimeError(httpx.stderr.strip() or "httpx failed")

    live_lines = [line.strip() for line in live_hosts_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    shodan_data = [_shodan_host(ip) for ip in _extract_ips(live_lines)]
    write_json(shodan_json, shodan_data)

    nuclei_lines: list[str] = []
    if quick:
        nuclei_file.write_text("", encoding="utf-8")
    else:
        nuclei_cmd = [str(nuclei_bin), "-l", str(live_hosts_file), "-silent"]
        for template_dir in SAFE_TEMPLATE_DIRS:
            nuclei_cmd.extend(["-t", template_dir])
        nuclei = _run(nuclei_cmd, output_path=nuclei_file)
        if nuclei.returncode != 0:
            raise RuntimeError(nuclei.stderr.strip() or "nuclei failed")
        nuclei_lines = [line.strip() for line in nuclei_file.read_text(encoding="utf-8").splitlines() if line.strip()]

    summary_text = summarize_run(target, live_lines, shodan_data, nuclei_lines)
    summary_file.write_text(summary_text, encoding="utf-8")
    write_json(
        meta_file,
        {
            "target": target,
            "quick": quick,
            "run_dir": str(run_dir),
            "subdomains_found": len(trimmed_subs),
            "live_hosts_found": len(live_lines),
            "shodan_hosts": len(shodan_data),
            "nuclei_findings": len(nuclei_lines),
            "artifacts": {
                "raw_subs": str(raw_subs),
                "live_hosts": str(live_hosts_file),
                "shodan_enriched": str(shodan_json),
                "nuclei_findings": str(nuclei_file),
                "summary": str(summary_file),
            },
        },
    )
    return run_dir


_NUCLEI_LINE_RE = re.compile(r"^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)")


def family_verdict(run_dir: Path | None) -> dict[str, Any]:
    """Семейный контракт banshee: вердикт + находки поверх готового run_dir.

    Вердикт ставит КОД по артефактам прогона, ноль обращений к модели:
      ПРОВАЛ       → rc 1   nuclei дал находки на живой поверхности
      ПРОШЁЛ       → rc 0   поверхность живая, проб не дало
      НЕ ПРОВЕРЕНО → rc 2   прогона нет / артефакты неполны (проверка не состоялась)

    🔴 Различение того же рода, что у notary: rc=2 похож на rc=1, но это не решение.
    Recon картографирует поверхность; он НЕ доказывает эксплуатируемость и НЕ
    доказывает безопасность цели — только то, что гейт авторизации пустил скан.
    """
    if run_dir is None or not (run_dir / "run.json").exists():
        return {
            "verdict": "НЕ ПРОВЕРЕНО", "rc": 2,
            "почему": "прогон не найден — проверка не состоялась",
            "findings": [], "not_proven": "recon не прогонялся; вердикта нет",
        }
    meta = read_json(run_dir / "run.json")
    nuclei_file = run_dir / "nuclei_findings.txt"
    nuclei_lines: list[str] = []
    if nuclei_file.exists():
        nuclei_lines = [line.strip() for line in
                        nuclei_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    findings: list[dict[str, Any]] = []
    for line in nuclei_lines:
        m = _NUCLEI_LINE_RE.match(line)
        вектор = m.group(1) if m else "recon-surface"
        findings.append({"вердикт": "ПРОВАЛ", "вектор": вектор, "почему": line})
    verdict = "ПРОВАЛ" if findings else "ПРОШЁЛ"
    return {
        "инструмент": {"имя": "banshee", "цель": meta.get("target", "")},
        "verdict": verdict,
        "rc": 1 if verdict == "ПРОВАЛ" else 0,
        "findings": findings,
        "счёт": {
            "subdomains": meta.get("subdomains_found", 0),
            "live_hosts": meta.get("live_hosts_found", 0),
            "shodan_enriched": meta.get("shodan_hosts", 0),
            "nuclei_findings": meta.get("nuclei_findings", 0),
        },
        "not_proven": (
            "recon картографирует поверхность и НЕ доказывает эксплуатируемость "
            "находок, безопасность цели или полноту картирования. Гейт scope "
            "подтверждает авторизацию цели, не её безопасность. Verdict ПРОВАЛ — "
            "это находки поверхности, а не успешная атака."
        ),
    }


def list_runs() -> list[dict[str, str]]:
    root = RECON_ROOT
    if not root.exists():
        return []
    rows: list[dict[str, str]] = []
    for target_path in sorted(root.iterdir()):
        if not target_path.is_dir():
            continue
        latest = latest_run_dir(target_path.name)
        if latest:
            rows.append({"target": target_path.name, "latest_run": latest.name, "path": str(latest)})
    return rows


def latest_summary(target: str) -> Path:
    latest = latest_run_dir(target)
    if latest is None:
        raise FileNotFoundError(f"no runs found for target: {target}")
    summary = latest / "summary.md"
    if not summary.exists():
        raise FileNotFoundError(f"summary missing for target: {target}")
    return summary

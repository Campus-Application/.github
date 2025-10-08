#!/usr/bin/env python3
import os
import re
import sys
import json
import time
import yaml
import hashlib
import textwrap
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import requests

GITHUB_API = "https://api.github.com"

@dataclass
class RepoRef:
    label: str
    url: str
    owner: str
    repo: str
    alerts_total: Optional[int] = None
    by_severity: Dict[str, int] = field(default_factory=dict)

def parse_repo(url: str) -> Tuple[str, str]:
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)(?:/|$)", url.strip())
    if not m:
        raise ValueError(f"Not a GitHub repo URL: {url}")
    return m.group(1), m.group(2)

def get_token() -> Optional[str]:
    # Prefer GH_TOKEN, then GITHUB_TOKEN
    return os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")

def fetch_dependabot_counts(owner: str, repo: str, session: requests.Session) -> Tuple[int, Dict[str, int]]:
    """
    Returns (total_count, by_severity) for open alerts.
    Follows pagination by chasing the 'next' link (works for page/cursor styles).
    Requires token with 'security_events:read' (private) or 'public_repo' (public).
    """
    headers = {"Accept": "application/vnd.github+json"}
    token = get_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"

    url = f"{GITHUB_API}/repos/{owner}/{repo}/dependabot/alerts?state=open&per_page=100"
    total = 0
    severities = {"critical": 0, "high": 0, "moderate": 0, "low": 0}

    while url:
        r = session.get(url, headers=headers, timeout=30)
        if r.status_code == 404:
            # Repo might be archived or alerts disabled
            return (0, severities)
        if r.status_code == 401 or r.status_code == 403:
            # Permissions missing
            raise RuntimeError(f"Auth/permission error for {owner}/{repo}: HTTP {r.status_code} - {r.text}")
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict) and "message" in data and "Not Found" in data["message"]:
            return (0, severities)
        if not isinstance(data, list):
            # Unexpected but do not crash
            break
        total += len(data)
        for alert in data:
            sev = (alert.get("security_vulnerability", {}) or {}).get("severity") or alert.get("severity")
            if sev:
                sev = sev.lower()
                if sev in severities:
                    severities[sev] += 1
        # pagination: follow Link: rel="next"
        link = r.headers.get("Link", "")
        next_url = None
        if link:
            parts = [p.strip() for p in link.split(",")]
            for part in parts:
                if 'rel="next"' in part:
                    m = re.search(r'<([^>]+)>', part)
                    if m:
                        next_url = m.group(1)
                        break
        url = next_url

    return total, severities

def md_link(label: str, url: str) -> str:
    return f"[{label}]({url})"

def render_alerts_cell(total: Optional[int], sev: Dict[str, int]) -> str:
    if total is None:
        return "—"
    if total == 0:
        return "0"
    # compact summary
    bits = []
    for key in ["critical", "high", "moderate", "low"]:
        n = sev.get(key, 0)
        if n:
            icon = {"critical":"🟥","high":"🟧","moderate":"🟨","low":"🟩"}[key]
            bits.append(f"{icon} {key.capitalize()} {n}")
    return f"**{total}** " + ("(" + ", ".join(bits) + ")" if bits else "")

def build_table(tools: List[dict], include_alerts: bool = True) -> str:
    headers = ["Tool", "Operating Time", "Frontend", "Backend", "Other / Notes"]
    if include_alerts:
        headers.insert(2, "Dependabot Alerts")
    lines = ["| " + " | ".join(headers) + " |",
             "|------|----------------|"+ ("-------------|" if include_alerts else "") +"-----------|----------|----------------|"]
    session = requests.Session()

    for t in tools:
        name = t["name"]
        op = t.get("operating_time", "—")
        repos = t.get("repos", {})
        archived = t.get("archived", False)

        # Build repo cells and collect alert counts
        def repo_cell(key: str) -> Tuple[str, Optional[int], Dict[str,int]]:
            if key not in repos:
                return ("", None, {})
            entry = repos[key]
            if isinstance(entry, str):
                url = entry
                label = "Frontend" if key=="frontend" else "Backend"
            else:
                url = entry.get("url")
                label = entry.get("label", key.capitalize())
            owner, repo = parse_repo(url)
            total = None
            bysev = {}
            try:
                total, bysev = fetch_dependabot_counts(owner, repo, session)
            except Exception as e:
                # Show em dash on failure, but log to stderr
                print(f"[warn] {name}/{key}: {e}", file=sys.stderr)
            link = md_link(label, url)
            return (link, total, bysev)

        fe_link, fe_total, fe_sev = repo_cell("frontend")
        be_link, be_total, be_sev = repo_cell("backend")

        # Other links (list)
        others = []
        for item in repos.get("other", []):
            label = item["label"]
            url = item["url"]
            others.append(md_link(label, url))
        other_cell = ", ".join(others)

        if "Dependabot Alerts" in headers:
            # Strategy: prefer FE count if present, else BE; if both present, sum both
            totals = [x for x in [fe_total, be_total] if x is not None]
            sum_total = sum(totals) if totals else None
            combined_sev = {"critical":0,"high":0,"moderate":0,"low":0}
            for sev in [fe_sev, be_sev]:
                for k in combined_sev:
                    combined_sev[k] += sev.get(k,0)
            alerts_cell = render_alerts_cell(sum_total, combined_sev)
            row = f"| **{name}** | {op} | {alerts_cell} | {fe_link} | {be_link} | {other_cell} |"
        else:
            row = f"| **{name}** | {op} | {fe_link} | {be_link} | {other_cell} |"

        if archived:
            row = row.replace(f"**{name}**", f"**{name}** 🗄️")

        lines.append(row)

    return "\n".join(lines)

def main():
    out_file = os.getenv("OUTPUT_MD", "Campus_Applications_Consolidated.md")
    title = "# 🎓 Campus Applications — Consolidated Overview\n"
    with open("data/tools.yaml", "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    table_md = build_table(cfg["tools"], include_alerts=True)
    content = f"{title}\n{table_md}\n"

    Path(out_file).write_text(content, encoding="utf-8")
    print(f"Wrote {out_file}")

if __name__ == "__main__":
    main()

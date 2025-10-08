#!/usr/bin/env python3
import argparse
import os
import re
import sys
import yaml
import requests
from pathlib import Path
from typing import Dict, Tuple, Optional, List

GITHUB_API = "https://api.github.com"

def parse_repo(url: str) -> Tuple[str, str]:
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)(?:/|$)", url.strip())
    if not m:
        raise ValueError(f"Not a GitHub repo URL: {url}")
    return m.group(1), m.group(2)

def get_token() -> Optional[str]:
    return os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")

def fetch_dependabot_counts(owner: str, repo: str, session: requests.Session):
    """
    Returns (total_count, by_severity, meta) for open alerts.
    meta contains keys like {"archived": bool, "reason": "archived|not_found|ok|forbidden"}.
    We silence warnings for archived/no-access repos by returning meta flags instead of raising.
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
        # Graceful handling
        if r.status_code == 404:
            return (None, {}, {"reason": "not_found"})
        if r.status_code == 403:
            msg = (r.text or "").lower()
            if "archived" in msg:
                return (None, {}, {"archived": True, "reason": "archived"})
            return (None, {}, {"reason": "forbidden"})
        if r.status_code == 401:
            return (None, {}, {"reason": "unauthorized"})
        r.raise_for_status()

        data = r.json()
        if not isinstance(data, list):
            return (None, {}, {"reason": "unexpected"})

        total += len(data)
        for alert in data:
            sev = (alert.get("security_vulnerability", {}) or {}).get("severity") or alert.get("severity")
            if isinstance(sev, str):
                sev = sev.lower()
                if sev in severities:
                    severities[sev] += 1

        # pagination
        link = r.headers.get("Link", "")
        next_url = None
        if link:
            for part in [p.strip() for p in link.split(",")]:
                if 'rel="next"' in part:
                    m = re.search(r'<([^>]+)>', part)
                    if m:
                        next_url = m.group(1)
                        break
        url = next_url

    return (total, severities, {"reason": "ok"})

def md_link(label: str, url: str) -> str:
    return f"[{label}]({url})"

def cell_link(entry, default_label: str) -> str:
    if entry is None:
        return ""
    if isinstance(entry, str):
        s = entry.strip()
        if s == "?":
            return "?"
        return md_link(default_label, s)
    url = entry.get("url", "").strip()
    lbl = entry.get("label", default_label)
    if not url:
        return ""
    return md_link(lbl, url)

def build_standard_table(cfg: dict) -> str:
    """No alerts inlined; just the original consolidated table. Archived tools are hidden."""
    header = "| Tool | Azure Operating Time | Frontend | Backend | Other / Notes |\n"
    sep = "|------|----------------------|-----------|----------|----------------|\n"
    lines = [header, sep]
    for t in cfg["tools"]:
        if t.get("archived"):
            continue  # hide archived tools
        name = f"**{t['name']}**"
        op = t.get("azure_operating_time", "—")
        repos = t.get("repos", {})
        fe = cell_link(repos.get("frontend"), "Frontend")
        be = cell_link(repos.get("backend"), "Backend")
        others = []
        for item in repos.get("other", []):
            if isinstance(item, str) and item.strip() == "?":
                others.append("?")
            else:
                others.append(cell_link(item, "Repository"))
        other_cell = ", ".join([o for o in others if o])
        lines.append(f"| {name} | {op} | {fe or ''} | {be or ''} | {other_cell} |\n")
    return "".join(lines)

def build_alerts_table(cfg: dict) -> str:
    """
    Separate alerts table, listing only repos with > 0 open alerts.
    Archived tools are hidden from this table as well.
    Sorted by Open (desc), then by Tool.
    Columns: Tool | Repo | Open | Critical | High | Moderate | Low
    """
    session = requests.Session()
    rows: List[dict] = []

    def consider_repo(tool_name: str, label: str, entry):
        if entry is None:
            return
        # skip placeholders
        if isinstance(entry, str):
            s = entry.strip()
            if s in {"?", ""}:
                return
            url = s
            lbl = label
        else:
            url = (entry.get("url") or "").strip()
            if not url:
                return
            lbl = entry.get("label", label)
        try:
            owner, repo = parse_repo(url)
        except ValueError:
            return

        total, sev, meta = fetch_dependabot_counts(owner, repo, session)
        # Only include repos with open > 0
        if not isinstance(total, int) or total <= 0:
            return

        row = {
            "tool": tool_name,
            "label": lbl,
            "url": url,
            "open": total,
            "critical": int(sev.get("critical", 0)) if isinstance(sev, dict) else "",
            "high": int(sev.get("high", 0)) if isinstance(sev, dict) else "",
            "moderate": int(sev.get("moderate", 0)) if isinstance(sev, dict) else "",
            "low": int(sev.get("low", 0)) if isinstance(sev, dict) else "",
        }
        rows.append(row)

    for t in cfg["tools"]:
        if t.get("archived"):
            continue  # hide archived tools completely
        tool = t["name"]
        repos = t.get("repos", {})
        consider_repo(tool, "Frontend", repos.get("frontend"))
        consider_repo(tool, "Backend", repos.get("backend"))
        for item in repos.get("other", []):
            consider_repo(tool, item.get("label", "Repository") if isinstance(item, dict) else "Repository", item)

    # Sort rows by open desc, then tool/name
    rows.sort(key=lambda r: (-r["open"], r["tool"], r["label"]))

    if not rows:
        return "_No open Dependabot alerts across listed repositories._\n"

    header = "| Tool | Repo | Open | Critical | High | Moderate | Low |\n"
    sep = "|------|------|-----:|--------:|-----:|---------:|----:|\n"
    lines = [header, sep]
    for r in rows:
        repo_link = md_link(r["label"], r["url"])
        lines.append(f"| **{r['tool']}** | {repo_link} | {r['open']} | {r['critical']} | {r['high']} | {r['moderate']} | {r['low']} |\n")
    return "".join(lines)

def replace_between_markers(text: str, start_marker: str, end_marker: str, replacement: str) -> str:
    pattern = re.compile(re.escape(start_marker) + r".*?" + re.escape(end_marker), re.DOTALL)
    block = f"{start_marker}\n\n{replacement}\n{end_marker}"
    if pattern.search(text):
        return pattern.sub(block, text, count=1)
    return text.rstrip() + "\n\n" + block + "\n"

def main():
    p = argparse.ArgumentParser(description="Build Campus Applications overview and alerts tables.")
    p.add_argument("--config", default="data/tools.yaml")
    p.add_argument("--output-md", default="Campus_Applications_Consolidated.md")
    p.add_argument("--update-readme", default="")
    p.add_argument("--start-marker", default="<!-- CAMPUS-OVERVIEW:START -->")
    p.add_argument("--end-marker", default="<!-- CAMPUS-OVERVIEW:END -->")
    args = p.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))

    # Compose final content
    title = "# 🎓 Campus Applications — Consolidated Overview\n\n"
    standard = build_standard_table(cfg)
    alerts_title = "\n\n## ⚠️ Dependabot Alerts — Weekly Snapshot\n\n_Note: only repositories with **> 0** open alerts are listed. Archived tools are hidden. Sorted by open alerts (desc)._\n\n"
    alerts_table = build_alerts_table(cfg)
    content = title + standard + alerts_title + alerts_table + "\n"

    if args.update_readme:
        readme_path = Path(args.update_readme)
        src = readme_path.read_text(encoding="utf-8")
        updated = replace_between_markers(src, args.start_marker, args.end_marker, content)
        readme_path.write_text(updated, encoding="utf-8")
        print(f"Updated section in {args.update_readme}")
    else:
        Path(args.output_md).write_text(content, encoding="utf-8")
        print(f"Wrote {args.output_md}")

if __name__ == "__main__":
    main()

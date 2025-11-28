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
    return (
        os.getenv("GH_TOKEN")
        or os.getenv("GITHUB_TOKEN")
        or os.getenv("SECURITY_READ_TOKEN")
        or os.getenv("SECURITY_READ_TOKEN_M")
        or os.getenv("TOKEN")
    )

def fetch_last_build_status(owner: str, repo: str, session: requests.Session) -> Optional[dict]:
    """Fetch the latest workflow run for the default branch."""
    headers = {"Accept": "application/vnd.github+json"}
    token = get_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"

    url = f"{GITHUB_API}/repos/{owner}/{repo}/actions/runs?per_page=1"
    r = session.get(url, headers=headers, timeout=30)
    if r.status_code != 200:
        return None
    data = r.json()
    runs = data.get("workflow_runs", [])
    if not runs:
        return None
    latest = runs[0]
    return {"conclusion": latest.get("conclusion"), "url": latest.get("html_url")}

def fetch_last_build_status_for_entry(entry, session):
    if entry is None:
        return None
    if isinstance(entry, str):
        url = entry.strip()
    else:
        url = entry.get("url", "").strip()
    if not url:
        return None
    try:
        owner, repo = parse_repo(url)
    except ValueError:
        return None
    return fetch_last_build_status(owner, repo, session)

def compute_repo_build_status(entry, session) -> str:
    build = fetch_last_build_status_for_entry(entry, session)
    if not build:
        return ""
    c = build["conclusion"]
    if c == "success":
        emoji = "🟢"
    elif c == "failure":
        emoji = "🔴"
    elif c == "cancelled":
        emoji = "⚪"
    else:
        emoji = "⚙️"
    return f"[{emoji}]({build['url']})"

def fetch_dependabot_counts(owner: str, repo: str, session: requests.Session):
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
            sev = (
                ((alert.get("security_vulnerability") or {}).get("severity"))
                or ((alert.get("security_advisory") or {}).get("severity"))
                or alert.get("severity")
            )
            if isinstance(sev, str):
                sev_l = sev.lower()
                if sev_l in severities:
                    severities[sev_l] += 1

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
    lbl = entry.get("label") or entry.get("name") or default_label
    if not url:
        return ""
    return md_link(lbl, url)

def build_standard_table(cfg: dict) -> str:
    session = requests.Session()
    header = "| Tool | Azure Operating Time | Frontend | Backend | Other / Notes |\n"
    sep = "|------|----------------------|-----------|----------|----------------|\n"
    lines = [header, sep]

    for t in cfg["tools"]:
        if t.get("archived"):
            continue
        name = f"**{t['name']}**"
        op = t.get("azure_operating_time", "—")
        repos = t.get("repos", {})

        # Frontend
        fe_link = cell_link(repos.get("frontend"), "Frontend")
        fe_build = compute_repo_build_status(repos.get("frontend"), session)
        fe_cell = f"{fe_link} {fe_build}".strip()

        # Backend
        be_link = cell_link(repos.get("backend"), "Backend")
        be_build = compute_repo_build_status(repos.get("backend"), session)
        be_cell = f"{be_link} {be_build}".strip()

        # Other
        other_cells = []
        for item in repos.get("other", []):
            link = cell_link(item, "Repository")
            build_status = compute_repo_build_status(item, session)
            if link or build_status:
                other_cells.append(f"{link} {build_status}".strip())
        other_cell = ", ".join(other_cells)

        lines.append(f"| {name} | {op} | {fe_cell or ''} | {be_cell or ''} | {other_cell} |\n")

    return "".join(lines)

def build_alerts_table(cfg: dict) -> str:
    session = requests.Session()
    rows: List[dict] = []

    def consider_repo(tool_name: str, label: str, entry):
        if entry is None:
            return
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
            lbl = entry.get("name", label)

        try:
            owner, repo = parse_repo(url)
        except ValueError:
            return

        total, sev, meta = fetch_dependabot_counts(owner, repo, session)
        if not isinstance(total, int) or total <= 0:
            return

        build = fetch_last_build_status(owner, repo, session)
        build_status = ""
        if build:
            c = build["conclusion"]
            if c == "success":
                emoji = "🟢"
            elif c == "failure":
                emoji = "🔴"
            elif c == "cancelled":
                emoji = "⚪"
            else:
                emoji = "⚙️"
            build_status = f"[{emoji}]({build['url']})"

        row = {
            "tool": tool_name,
            "label": lbl,
            "url": url,
            "build": build_status,
            "open": total,
            "critical": int(sev.get("critical", 0)),
            "high": int(sev.get("high", 0)),
            "moderate": (total - int(sev.get("critical", 0) - int(sev.get("high", 0) - int(sev.get("low", 0)),
            "low": int(sev.get("low", 0)),
        }
        rows.append(row)

    for t in cfg["tools"]:
        if t.get("archived"):
            continue
        tool = t["name"]
        repos = t.get("repos", {})
        consider_repo(tool, "Frontend", repos.get("frontend"))
        consider_repo(tool, "Backend", repos.get("backend"))
        for item in repos.get("other", []):
            consider_repo(tool, item.get("name", "Repository") if isinstance(item, dict) else "Repository", item)

    rows.sort(key=lambda r: (-r["open"], r["tool"], r["label"]))

    if not rows:
        return "_No open Dependabot alerts across listed repositories._\n"

    header = "| Tool | Repo | Build | Open | Critical | High | Moderate | Low |\n"
    sep = "|------|------|-------|-----:|--------:|-----:|---------:|----:|\n"
    lines = [header, sep]
    for r in rows:
        repo_link = md_link(r["label"], r["url"])
        lines.append(
            f"| **{r['tool']}** | {repo_link} | {r['build']} | {r['open']} | "
            f"{r['critical']} | {r['high']} | {r['moderate']} | {r['low']} |\n"
        )
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

    title = "# 🎓 Campus Applications — Consolidated Overview\n\n"
    standard = build_standard_table(cfg)
    alerts_title = (
        "\n\n## ⚠️ Dependabot Alerts — Weekly Snapshot\n\n"
        "_Note: only repositories with > 0 open alerts are listed. Archived tools are hidden._\n\n"
    )
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

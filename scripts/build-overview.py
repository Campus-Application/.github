#!/usr/bin/env python3
import argparse
import os
import re
import sys
import yaml
import requests
from pathlib import Path
from typing import Dict, Tuple, Optional

GITHUB_API = "https://api.github.com"

def parse_repo(url: str) -> Tuple[str, str]:
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)(?:/|$)", url.strip())
    if not m:
        raise ValueError(f"Not a GitHub repo URL: {url}")
    return m.group(1), m.group(2)

def get_token() -> Optional[str]:
    return os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")

def fetch_dependabot_counts(owner: str, repo: str, session: requests.Session) -> Tuple[int, Dict[str, int]]:
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
        if r.status_code in (401, 403):
            raise RuntimeError(f"Auth/permission error for {owner}/{repo}: HTTP {r.status_code} - {r.text}")
        if r.status_code == 404:
            # repo missing or alerts disabled
            return (0, severities)
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, list):
            break
        total += len(data)
        for alert in data:
            sev = (alert.get("security_vulnerability", {}) or {}).get("severity") or alert.get("severity")
            if isinstance(sev, str):
                sev = sev.lower()
                if sev in severities:
                    severities[sev] += 1
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
    return total, severities

def alert_badge(total: Optional[int], sev: Dict[str, int]) -> str:
    if total is None:
        return ""
    if total == 0:
        return " (0)"
    bits = []
    for key, icon in [("critical","🟥"),("high","🟧"),("moderate","🟨"),("low","🟩")]:
        n = sev.get(key, 0)
        if n:
            bits.append(f"{icon}{n}")
    return f" (**{total}** {' '.join(bits)})"

def link_with_alerts(label_or_dict, session: requests.Session) -> str:
    if isinstance(label_or_dict, str):
        if label_or_dict.strip() == "?":
            return "?"
        url = label_or_dict
        label = "Frontend" if "frontend" in label_or_dict.lower() else "Repository"
    else:
        url = label_or_dict.get("url", "").strip()
        label = label_or_dict.get("label", "Repository")
    if not url:
        return ""
    # fetch alerts
    total = None
    sev = {}
    try:
        owner, repo = parse_repo(url)
        total, sev = fetch_dependabot_counts(owner, repo, session)
    except Exception as e:
        print(f"[warn] {url}: {e}", file=sys.stderr)
    md = f"[{label}]({url})"
    md += alert_badge(total, sev)
    return md

def build_table(cfg: dict) -> str:
    session = requests.Session()
    header = "| Tool | Azure Operating Time | Frontend | Backend | Other / Notes |\n"
    sep = "|------|----------------------|-----------|----------|----------------|\n"
    lines = [header, sep]
    for t in cfg["tools"]:
        name = t["name"]
        if t.get("archived"):
            name_md = f"**{name}** 🗄️"
        else:
            name_md = f"**{name}**"
        op = t.get("azure_operating_time", "—")
        repos = t.get("repos", {})

        # Frontend cell
        fe = repos.get("frontend")
        fe_cell = ""
        if fe is None:
            fe_cell = ""
        elif isinstance(fe, str) and fe.strip() == "?":
            fe_cell = "?"
        else:
            fe_cell = link_with_alerts(fe, session)

        # Backend cell
        be = repos.get("backend")
        be_cell = ""
        if be is None:
            be_cell = ""
        elif isinstance(be, str) and be.strip() == "?":
            be_cell = "?"
        else:
            be_cell = link_with_alerts(be, session)

        # Other / Notes cell
        others = []
        for item in repos.get("other", []):
            if isinstance(item, str) and item.strip() == "?":
                others.append("?")
            else:
                others.append(link_with_alerts(item, session))
        other_cell = ", ".join(filter(None, others))

        lines.append(f"| {name_md} | {op} | {fe_cell} | {be_cell} | {other_cell} |\n")
    return "".join(lines)

def replace_between_markers(text: str, start_marker: str, end_marker: str, replacement: str) -> str:
    pattern = re.compile(re.escape(start_marker) + r".*?" + re.escape(end_marker), re.DOTALL)
    block = f"{start_marker}\n\n{replacement}\n{end_marker}"
    if pattern.search(text):
        return pattern.sub(block, text, count=1)
    # If markers not found, append at end
    return text.rstrip() + "\n\n" + block + "\n"

def main():
    p = argparse.ArgumentParser(description="Build Campus Applications overview table with inline Dependabot alerts.")
    p.add_argument("--config", default="data/tools.yaml")
    p.add_argument("--output-md", default="Campus_Applications_Consolidated.md")
    p.add_argument("--update-readme", default="")
    p.add_argument("--start-marker", default="<!-- CAMPUS-OVERVIEW:START -->")
    p.add_argument("--end-marker", default="<!-- CAMPUS-OVERVIEW:END -->")
    args = p.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    table = build_table(cfg)
    title = "# 🎓 Campus Applications — Consolidated Overview\n\n"
    content = title + table + "\n"

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

#!/usr/bin/env python3
"""
Leonida PR Security Monitor
Implements the Etoile-Bleu/leonida-reviews methodology for continuous PR monitoring.

Usage:
    python monitor.py --once                    # Single check
    python monitor.py --daemon --interval 300   # Run every 5 minutes
    python monitor.py --since-pr 8500           # Only check PRs after #8500
    python monitor.py --validate-only           # Validate existing reviews
"""

import argparse
import json
import os
import subprocess
import sys
import time
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

# ─── Constants ──────────────────────────────────────────────────────────────
REPO = "ItsNotRexed/Leonida"
REVIEW_REPO = "Etoile-Bleu/leonida-reviews"
STATE_FILE = Path(os.getenv("MONITOR_STATE_FILE", "monitor_state.json"))
REVIEWS_DIR = Path(os.getenv("MONITOR_REVIEWS_DIR", "reviews"))
VERDICTS = {"do-not-merge", "notes", "clean", "scan-only", "not-reviewed"}

# ─── Suspicious Patterns (from AGENT_PROMPT.md) ─────────────────────────────
# These are HIGH-SEVERITY patterns that indicate likely malicious behavior
# Patterns are designed to avoid false positives on legitimate Leonida code
SUSPICIOUS_PATTERNS = [
    # Code execution & persistence - HIGH SEVERITY
    (r"subprocess\.(run|Popen|call)\s*\([^)]*shell\s*=\s*True", "Shell command execution with shell=True"),
    (r"os\.system\s*\(", "Direct OS command execution"),
    (r"exec\s*\(\s*[^)]*compile\s*\(", "Compile + exec pattern"),
    (r"eval\s*\(\s*compile\s*\(", "Compile + eval pattern"),
    (r"__import__\s*\(\s*[\"'][^\"']*os[\"']", "Dynamic os module import"),
    (r"(powershell|cscript|wscript)\s+-Command\s+", "PowerShell command execution"),
    (r"cmd\.exe\s+/c\s+", "CMD command execution"),
    (r"reg\s+(add|delete)\s+HKLM|reg\s+(add|delete)\s+HKCU", "Registry persistence"),
    (r"schtasks\s+/create|at\s+\d{1,2}:\d{2}", "Scheduled task creation"),
    (r"LoadLibraryEx\s*\([^)]*LOAD_WITH_ALTERED_SEARCH_PATH", "DLL search order hijacking"),
    (r"curl\s+https?://[^|]+\|\s*(bash|sh|python)", "Download and pipe to shell"),
    (r"wget\s+https?://[^|]+\|\s*(bash|sh|python)", "Wget pipe to shell"),
    (r"base64\.(b64decode|decode)\s*\(\s*[\"'][A-Za-z0-9+/]{50,}[\"']", "Large base64 payload"),
    (r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}", "Multiple hex escapes (shellcode)"),
    (r"chr\s*\(\s*\d{3}\s*\)\s*\+\s*chr\s*\(", "Character code construction"),

    # Data exfiltration - HIGH SEVERITY
    (r"(api[_-]?key|secret[_-]?key|access[_-]?token|password)\s*=\s*[\"'][A-Za-z0-9_\-]{20,}[\"']", "Hardcoded long secret"),
    (r"ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}", "GitHub token in code"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----", "Private key in code"),
    (r"requests\.(get|post)\s*\(\s*[\"']https?://[^\"']*(api|webhook|collect|telemetry|exfil)[^\"']*[\"']", "Suspicious network endpoint"),

    # Supply chain - HIGH SEVERITY
    (r"pip\s+install\s+[^=\s]+\s*--index-url\s+https?://[^pypi]", "Non-standard package index"),
    (r"uses:\s*[^/]+/[^@]+@(main|master|latest)", "Unpinned GitHub Action"),
    (r"pull_request_target.*secrets\.", "Dangerous workflow with secrets"),
    (r"secrets\.(AWS|AZURE|GCP|DOCKER|NPM)_", "Cloud provider secrets in workflow"),

    # Leonida-specific prohibited content - HIGH SEVERITY
    (r"(game[_-]?data|executable|dump|decrypt)\s*(path|dir|folder)\s*=\s*[\"'][^\"']+[\"']", "Game data path configuration"),
    (r"check_no_game_data\s*=\s*False|no_game_data\s*=\s*False", "Security check disabled"),
]

# MEDIUM-SEVERITY patterns (require more context)
MEDIUM_PATTERNS = [
    (r"subprocess\.(run|Popen|call)\s*\([^)]*shell\s*=\s*True", "Shell=True in subprocess"),
    (r"eval\s*\(", "eval() usage"),
    (r"exec\s*\(", "exec() usage"),
    (r"compile\s*\(", "compile() usage"),
    (r"curl\s+https?://|wget\s+https?://", "Network download"),
    (r"base64\.(b64decode|decode)", "Base64 decoding"),
    (r"\\x[0-9a-f]{2}", "Hex escape sequence"),
    (r"\\u[0-9a-f]{4}", "Unicode escape"),
    (r"reg\s+(add|query|delete)", "Registry access"),
    (r"scheduled_task|schtasks", "Scheduled task reference"),
    (r"LoadLibrary|GetProcAddress", "Dynamic library loading"),
]

# LOW-SEVERITY / Context-dependent patterns (only flag if no legitimate context)
LOW_PATTERNS = [
    (r"(api[_-]?key|secret|token|password)", "Secret-like variable name"),
    (r"(shader|executable|dump|decrypt|key)", "Leonida-prohibited term"),
    (r"game[_-]?data", "Game data reference"),
]

# Legitimate contexts that strongly reduce false positives
LEGITIMATE_CONTEXTS = [
    "test_", "mock_", "fake_", "stub_", "example_", "sample_",
    "check_", "verify_", "validate_", "scan_", "audit_", "detect_",
    "security_", "hardening_", "sanitize_", "escape_", "encode_", "decode_",
    "parse_", "extract_", "analyze_", "inspect_", "review_",
    "benchmark_", "benchmarking_", "fuzz_", "fuzzing_",
    "test/", "tests/", "test_", "_test", ".test.",
    "semantic/", "test_", "_test.py",
    "shader", "shaders/", "shader_", ".asm", ".spv", ".spvasm",
    "executable", "executable_path", "executable_name",
    "dump", "dump_path", "dump_dir", "dump_file", "dump_output",
    "key", "key_path", "key_name", "key_file", "keyboard", "keymap",
    "shader", "shader_", "shader_stage", "shader_module", "shader_binary",
    "dump", "dumped", "dumping", "dumper",
    "scheduled", "schedule", "scheduler",
    "at 0", "at 1", "at 2", "at 3", "at 4", "at 5",
    "at 10", "at 20", "at 30", "at 40", "at 50",
    "at 100", "at 200", "at 300", "at 400", "at 500",
    "unicode", "unicode_", "utf8", "utf-8", "utf16", "utf-16",
    "hex", "hex_", "hexdump", "hex_dump",
    "executable", "executable_path", "executable_file",
    "shader", "shader_", "shader_stage", "shader_module",
    "bc6h", "bc7", "bc1", "bc2", "bc3", "bc4", "bc5",
    "texture", "tex_", "texel",
    "shader", "shader_", "vertex", "fragment", "compute", "geometry",
    "dump", "dump_", "dumped", "dumper",
    "shader", "shaders", "shader_",
]


def run_cmd(cmd: List[str], cwd: Optional[Path] = None, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run command with proper encoding handling."""
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, encoding='utf-8', errors='replace')


def gh_pr_list(state: str = "open", limit: int = 100) -> List[Dict]:
    """Get PR list from GitHub."""
    result = run_cmd(["gh", "pr", "list", "--repo", REPO, "--state", state, "--limit", str(limit),
                      "--json", "number,title,author,headRefName,baseRefName,headRefOid,createdAt,updatedAt,comments,reviewDecision,url"])
    if result.returncode != 0:
        raise RuntimeError(f"gh pr list failed: {result.stderr}")
    return json.loads(result.stdout)


def gh_pr_diff(pr_number: int) -> str:
    """Get PR diff."""
    result = run_cmd(["gh", "pr", "diff", str(pr_number), "--repo", REPO])
    if result.returncode != 0:
        raise RuntimeError(f"gh pr diff failed: {result.stderr}")
    return result.stdout


def gh_pr_view(pr_number: int) -> Dict:
    """Get PR metadata."""
    result = run_cmd(["gh", "pr", "view", str(pr_number), "--repo", REPO,
                      "--json", "number,title,body,author,headRefOid,baseRefName,headRefName,files,commits,url"])
    if result.returncode != 0:
        raise RuntimeError(f"gh pr view failed: {result.stderr}")
    return json.loads(result.stdout)


def load_state() -> Dict:
    """Load monitoring state."""
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"reviewed": {}, "last_check": None, "last_pr": 0}


def save_state(state: Dict):
    """Save monitoring state."""
    STATE_FILE.write_text(json.dumps(state, indent=2))


def is_legitimate_context(text: str, match_start: int) -> bool:
    """Check if match is in legitimate context."""
    context = text[max(0, match_start - 300):match_start + 300].lower()
    return any(prefix in context for prefix in LEGITIMATE_CONTEXTS)


def scan_diff(diff: str, files: List[Dict]) -> List[Dict]:
    """Scan added lines only; removed/context lines must never create findings."""
    import re

    findings = []
    current_file = None
    new_line_number = 0

    for line in diff.splitlines():
        if line.startswith("diff --git "):
            current_file = None
            new_line_number = 0
            continue
        if line.startswith("+++ "):
            path = line[4:].strip()
            current_file = path[2:] if path.startswith("b/") else path
            continue
        if line.startswith("@@ "):
            import re as _re
            match = _re.search(r"\+(\d+)", line)
            new_line_number = int(match.group(1)) if match else 0
            continue
        if line.startswith("\\") or not current_file:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added_text = line[1:]
            tiers = ((SUSPICIOUS_PATTERNS, "high", "critical"),
                     (MEDIUM_PATTERNS, "medium", "suspicious"),
                     (LOW_PATTERNS, "low", "contextual"))
            for patterns, severity, tier in tiers:
                for pattern, desc in patterns:
                    for match in re.finditer(pattern, added_text, re.IGNORECASE):
                        findings.append({
                            "file": current_file,
                            "line": new_line_number,
                            "pattern": desc,
                            "match": match.group()[:100],
                            "context": added_text.strip()[:200],
                            "severity": severity,
                            "tier": tier,
                        })
        if not line.startswith("-"):
            new_line_number += 1

    # Remove exact duplicate findings generated by overlapping pattern tiers.
    unique = []
    seen = set()
    for finding in findings:
        key = (finding["file"], finding["line"], finding["pattern"], finding["match"])
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def analyze_pr(pr_number: int, head_sha: str) -> Dict:
    """Perform complete security review of a PR."""
    print(f"  Analyzing PR #{pr_number}...")

    # Get PR details
    pr_data = gh_pr_view(pr_number)
    diff = gh_pr_diff(pr_number)

    # Scan for patterns
    findings = scan_diff(diff, pr_data.get('files', []))

    # Determine verdict
    if not findings:
        verdict = "clean"
    else:
        high_findings = [f for f in findings if f["severity"] == "high"]
        if high_findings:
            verdict = "do-not-merge"
        else:
            verdict = "notes"

    # Build review object
    review = {
        "pr": pr_number,
        "head_sha": head_sha,
        "reviewer": f"{os.getenv('USER', 'monitor')}/automated",
        "date": datetime.now(timezone.utc).date().isoformat(),
        "scope": "static, automated, diff only, nothing executed",
        "verdict": verdict,
        "findings": [f"{f['file']}:{f['line']} - {f['pattern']} - {f['match']}" for f in findings],
        "detailed_findings": findings,
        "read_by_human": False,
        "commented_on_github": False,
        "pr_title": pr_data.get('title', ''),
        "pr_url": pr_data.get('url', ''),
        "author": pr_data.get('author', {}).get('login', ''),
        "base_branch": pr_data.get('baseRefName', ''),
        "head_branch": pr_data.get('headRefName', ''),
        "file_count": len(pr_data.get('files', [])),
        "additions": sum(f.get('additions', 0) for f in pr_data.get('files', [])),
        "deletions": sum(f.get('deletions', 0) for f in pr_data.get('files', [])),
    }

    return review


def save_review(review: Dict):
    """Save review to reviews/<pr>.json."""
    REVIEWS_DIR.mkdir(exist_ok=True)
    review_file = REVIEWS_DIR / f"{review['pr']}.json"

    # If review exists, preserve some fields
    if review_file.exists():
        existing = json.loads(review_file.read_text())
        if existing.get('head_sha') == review['head_sha']:
            # Same commit - preserve human flags
            review['read_by_human'] = existing.get('read_by_human', False)
            review['commented_on_github'] = existing.get('commented_on_github', False)

    review_file.write_text(json.dumps(review, indent=2))
    return review_file


def validate_review(review: Dict) -> bool:
    """Validate review against schema."""
    required = {"pr", "head_sha", "reviewer", "date", "scope", "verdict", "findings",
                "read_by_human", "commented_on_github"}
    if not all(k in review for k in required):
        return False
    if review["verdict"] not in VERDICTS:
        return False
    if not isinstance(review["findings"], list):
        return False
    if not isinstance(review["read_by_human"], bool) or not isinstance(review["commented_on_github"], bool):
        return False
    return True


def check_rate_limit() -> int:
    """Check remaining GitHub API rate limit."""
    result = run_cmd(["gh", "api", "rate_limit"])
    if result.returncode == 0:
        data = json.loads(result.stdout)
        return data.get("rate", {}).get("remaining", 0)
    return 5000


def main():
    parser = argparse.ArgumentParser(description="Leonida PR Security Monitor")
    parser.add_argument("--once", action="store_true", help="Run single check")
    parser.add_argument("--daemon", action="store_true", help="Run continuously")
    parser.add_argument("--interval", type=int, default=300, help="Check interval in seconds (default: 300)")
    parser.add_argument("--since-pr", type=int, default=0, help="Only check PRs after this number")
    parser.add_argument("--validate-only", action="store_true", help="Only validate existing reviews")
    parser.add_argument("--limit", type=int, default=100, help="Max PRs to check per run")
    args = parser.parse_args()

    print(f"[{datetime.now()}] Leonida PR Security Monitor started")
    print(f"Repository: {REPO}")

    # Check rate limit
    remaining = check_rate_limit()
    print(f"GitHub API remaining: {remaining}")

    if args.validate_only:
        # Validate existing reviews
        for review_file in REVIEWS_DIR.glob("*.json"):
            review = json.loads(review_file.read_text())
            if not validate_review(review):
                print(f"INVALID: {review_file}")
            else:
                print(f"OK: {review_file.name}")
        return 0

    state = load_state()
    reviewed = state.get("reviewed", {})

    while True:
        try:
            print(f"\n[{datetime.now()}] Checking PRs...")

            # Get open PRs
            prs = gh_pr_list("open", args.limit)
            print(f"Found {len(prs)} open PRs")

            for pr in prs:
                pr_num = pr["number"]
                head_sha = pr["headRefOid"]

                # Skip if below threshold
                if pr_num <= args.since_pr:
                    continue

                # Check if already reviewed at this commit
                key = f"{pr_num}:{head_sha}"
                if key in reviewed:
                    print(f"  PR #{pr_num} already reviewed at {head_sha[:8]}")
                    continue

                # Analyze PR
                review = analyze_pr(pr_num, head_sha)
                save_review(review)

                if not validate_review(review):
                    print(f"  ERROR: Review validation failed for PR #{pr_num}")
                    continue

                # Update state
                reviewed[key] = {
                    "pr": pr_num,
                    "head_sha": head_sha,
                    "verdict": review["verdict"],
                    "reviewed_at": datetime.now(timezone.utc).isoformat()
                }

                # Print summary
                print(f"  PR #{pr_num}: {review['verdict'].upper()} - {review['pr_title'][:60]}")
                if review["findings"]:
                    for f in review["findings"][:3]:
                        print(f"    - {f}")
                    if len(review["findings"]) > 3:
                        print(f"    ... and {len(review['findings']) - 3} more")

            # Save state
            state["reviewed"] = reviewed
            state["last_check"] = datetime.now(timezone.utc).isoformat()
            state["last_pr"] = max([p["number"] for p in prs]) if prs else 0
            save_state(state)

            print(f"[{datetime.now()}] Check complete. Reviewed {len(prs)} PRs.")

            if not args.daemon or args.once:
                break

            # Wait for next interval
            print(f"Sleeping {args.interval} seconds...")
            time.sleep(args.interval)

        except KeyboardInterrupt:
            print("\nInterrupted by user")
            break
        except Exception as e:
            print(f"ERROR: {e}")
            if not args.daemon:
                raise
            time.sleep(60)  # Wait before retry

    return 0


if __name__ == "__main__":
    sys.exit(main())
#!/usr/bin/env python3
"""Heuristic static PR monitor. Never executes contributor code."""
import argparse, difflib, hashlib, json, os, re, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

REPO = "ItsNotRexed/Leonida"
STATE = Path(os.getenv("MONITOR_STATE_FILE", "monitor_state.json"))
OUT = Path(os.getenv("MONITOR_REVIEWS_DIR", "reviews"))
QUEUE = OUT / "comment_queue.json"
BATCH_QUEUE_FILE = Path(os.getenv("MONITOR_BATCH_QUEUE_FILE", "historical_pr_batches.json"))
BATCH_REPORT_FILE = Path(os.getenv("MONITOR_BATCH_REPORT_FILE", "historical_batch_findings.json"))
BATCH_RESULTS_DIR = Path(os.getenv("MONITOR_BATCH_RESULTS_DIR", "historical-scan-output"))
LEDGER_INDEX_FILE = Path(os.getenv("MONITOR_REVIEW_INDEX_FILE", "docs/reviews.json"))
LEDGER_REVIEWS_DIR = Path(os.getenv("MONITOR_LEDGER_REVIEWS_DIR", "reviews"))
SOURCE = "leonida-security-monitor"
HIGH = [
 (r"\b(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection)\b", "Process injection"),
 (r"\b(?:keylog(?:ger|ging)|GetAsyncKeyState)\b", "Keylogging"),
 (r"\b(?:reverse|bind)\s*shell\b|/dev/tcp/\d", "Reverse/bind shell"),
 (r"\b(?:schtasks\s+/create|New-ScheduledTask|crontab\s+-e)\b", "Persistence mechanism"),
 (r"\b(?:CurrentVersion\\Run|LaunchAgents|systemd/system)\b", "Autostart persistence"),
 (r"\b(?:ransomware|encrypt_files|vssadmin\s+delete|shadowcopy\s+delete)\b", "Ransomware-like behavior"),
 (r"\b(?:credential|password|cookie|token)\s*(?:dump|steal|exfiltrat)", "Credential theft/exfiltration"),
 (r"\b(?:curl|wget)\b[^\n]{0,160}\|\s*(?:sh|bash|python)\b", "Download piped to interpreter"),
 (r"\b(?:IEX|Invoke-Expression)\b.{0,100}(?:DownloadString|WebClient|https?://)", "PowerShell download-and-execute"),
 (r"\b(?:FromBase64String|b64decode)\b.{0,100}\b(?:exec|eval)\s*\(", "Decoded payload execution"),
 (r"\bcheck_no_game_data\s*=\s*False|\bno_game_data\s*=\s*False", "Leonida safeguard disabled"),
]
MEDIUM = [
 (r"(?<![A-Za-z0-9_.])(?:eval|exec|compile)\s*\(", "Dynamic code execution"),
 (r"\b(?:subprocess\.(?:run|Popen|call)|os\.system)\s*\(", "OS command execution"),
 (r"\b(?:requests\.(?:get|post)|urlopen|httpx\.(?:get|post))\s*\(", "Network request"),
 (r"\b(?:ctypes|cffi)\b|\bLoadLibrary(?:Ex)?\s*\(", "Native library loading"),
 (r"\b(?:base64|binascii)\.(?:b64decode|unhexlify)\s*\(", "Encoded payload handling"),
 (r"\b(?:reg\s+add|winreg\.SetValue|schtasks)\b", "Persistence/registry operation"),
 (r"\b(?:shell\s*=\s*True|--index-url|extra-index-url)\b", "Shell execution or package source override"),
 (r"\b(?:api[_-]?key|secret|access[_-]?token|password)\s*[:=]\s*['\"][^'\"]{12,}['\"]", "Possible hardcoded secret"),
]
# Generic words common in graphics/recompilation code (for example "shader" or
# "executable") are not security indicators by themselves. Keep low severity
# limited to explicit unfinished-work markers; never flag terminology alone.
# TODO-like words and identifiers are too ambiguous in normal source code.
# Keep this list empty; actionable findings must use higher-signal rules.
LOW = []
SAFE_PATH = re.compile(r"(^|/)(tests?|docs?|examples?|fixtures?)(/|$)|\.(md|rst|txt)$", re.I)
SAFE_WORDS = re.compile(r"\b(mock|fixture|example|test case|not executed|placeholder)\b", re.I)

class RateLimited(Exception): pass

def now(): return datetime.now(timezone.utc).isoformat()

def gh(args, timeout=600):
    for attempt in range(4):
        p = subprocess.run(["gh", *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        if p.returncode == 0: return p.stdout
        msg = (p.stderr or p.stdout).strip()
        limited = any(x in msg.lower() for x in ("secondary rate limit", "abuse detection", "api rate limit exceeded", "http 429", "http 403"))
        if not limited: raise RuntimeError(msg[:600])
        if attempt == 3: raise RateLimited(msg)
        delay = min(900, 60 * (2 ** attempt))
        print(f"RATE LIMIT: backing off {delay}s ({attempt+1}/3)", flush=True)
        time.sleep(delay)
    raise RateLimited("Retry budget exhausted")

def get_prs(limit):
    return json.loads(gh(["pr","list","--repo",REPO,"--state","open","--limit",str(limit),
      "--json","number,title,body,author,headRefOid,baseRefName,headRefName,url"]))

def parse_pr_ranges(value):
    ranges = []
    for part in (value or "").split(","):
        part = part.strip()
        if not part:
            continue
        match = re.fullmatch(r"(\d+)\s*-\s*(\d+)", part)
        if not match:
            raise ValueError(f"Invalid PR range {part!r}; expected START-END.")
        start, end = map(int, match.groups())
        if start < 1 or end < start:
            raise ValueError(f"Invalid PR range {part!r}.")
        ranges.append((start, end))
    if not ranges:
        raise ValueError("No PR ranges supplied.")
    return ranges


def load_ledger_index():
    if not LEDGER_INDEX_FILE.exists():
        return {}
    try:
        rows = json.loads(LEDGER_INDEX_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Could not read review ledger index {LEDGER_INDEX_FILE}: {exc}") from exc
    result = {}
    for row in rows if isinstance(rows, list) else []:
        try:
            number = int(row.get("pr"))
        except (TypeError, ValueError):
            continue
        result[number] = {
            "head": str(row.get("head") or "").lower(),
            "verdict": str(row.get("verdict") or "")
        }
    return result


def is_currently_checked(number, head_sha, state, ledger_index):
    key = f"{number}:{head_sha}"
    if key in state.get("reviewed", {}):
        return "state"
    prior = ledger_index.get(number)
    if not prior:
        return ""
    prefix = prior.get("head", "")
    if len(prefix) < 7 or not head_sha.lower().startswith(prefix):
        return ""
    verdict = prior.get("verdict", "")
    if verdict == "not-reviewed":
        return ""
    if verdict == "in-progress":
        return "claimed"
    return "ledger"


def get_all_prs():
    projection = (
        ".[] | {number: .number, title: (.title // \"\"), "
        "author: {login: (.user.login // \"\")}, "
        "headRefOid: (.head.sha // \"\"), baseRefName: (.base.ref // \"\"), "
        "headRefName: (.head.ref // \"\"), url: (.html_url // \"\"), "
        "state: (.state // \"unknown\"), merged_at: .merged_at} | @json"
    )
    raw = gh(["api", "--paginate", "--jq", projection,
              f"repos/{REPO}/pulls?state=all&per_page=100"], timeout=900)
    prs = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, str):
                item = json.loads(item)
            if isinstance(item, dict) and item.get("number"):
                prs.append(item)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Could not parse paginated PR inventory row: {exc}") from exc
    return prs


def save_state(state):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


def seed_historical_batches(state, value):
    if BATCH_QUEUE_FILE.exists():
        raise RuntimeError(
            f"Historical batch queue already exists at {BATCH_QUEUE_FILE}; refusing to reseed it."
        )
    ranges = parse_pr_ranges(value)
    all_prs = get_all_prs()
    ledger_index = load_ledger_index()
    state.setdefault("reviewed", {})
    tasks = []
    summaries = []

    for start, end in ranges:
        label = f"{start}-{end}"
        selected = [p for p in all_prs if start <= int(p.get("number", 0)) <= end]
        selected.sort(key=lambda p: int(p["number"]))
        stats = {
            "range": label,
            "total_prs": len(selected),
            "already_checked": 0,
            "active_claims": 0,
            "queued": 0,
            "missing_head": 0,
            "scanned": 0,
            "high_alerts": 0,
            "medium_signal_prs": 0
        }
        for p in selected:
            number = int(p["number"])
            sha = str(p.get("headRefOid") or "")
            if not sha:
                stats["missing_head"] += 1
                continue
            checked = is_currently_checked(number, sha, state, ledger_index)
            if checked == "claimed":
                stats["active_claims"] += 1
                continue
            if checked:
                stats["already_checked"] += 1
                continue
            tasks.append({
                "pr": number,
                "head_sha": sha,
                "range": label,
                "state": p.get("state", "unknown"),
                "merged": bool(p.get("merged_at"))
            })
            stats["queued"] += 1
        summaries.append(stats)

    BATCH_QUEUE_FILE.parent.mkdir(parents=True, exist_ok=True)
    BATCH_QUEUE_FILE.write_text(
        json.dumps({"schema": 1, "ranges": summaries, "tasks": tasks}, separators=(",", ":")) + "\n",
        encoding="utf-8"
    )
    state["historical_batch"] = {
        "ranges": summaries,
        "total_tasks": len(tasks),
        "seeded_at": now(),
        "queue_file": str(BATCH_QUEUE_FILE)
    }
    state["batch_queue_cursor"] = 0
    state.pop("batch_waiting", None)
    save_state(state)

    print(f"Historical PR inventory fetched: {len(all_prs)} PRs across all states.", flush=True)
    for stats in summaries:
        print(
            "Batch #{range}: {total_prs} PRs; {already_checked} already checked; "
            "{active_claims} active claims deferred; {queued} queued; {missing_head} missing head SHA.".format(**stats),
            flush=True
        )
    print(f"Total queued for fresh scans: {len(tasks)}.", flush=True)


def current_batch_stats(state, label):
    batch = state.get("historical_batch", {})
    for item in batch.get("ranges", []):
        if item.get("range") == label:
            return item
    return None


def run_historical_batch(args, state):
    if not BATCH_QUEUE_FILE.exists():
        return False
    try:
        data = json.loads(BATCH_QUEUE_FILE.read_text(encoding="utf-8"))
        tasks = data.get("tasks", [])
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError(f"Could not read historical batch queue: {exc}") from exc
    if not isinstance(tasks, list):
        raise RuntimeError("Historical batch queue has an invalid tasks list.")

    cursor = int(state.get("batch_queue_cursor", 0))
    if cursor >= len(tasks):
        batch = state.setdefault("historical_batch", {})
        if not batch.get("completed_at"):
            batch["completed_at"] = now()
            save_state(state)
        print(f"Historical batch queue complete: {len(tasks)} queued PRs processed.", flush=True)
        return False

    ledger_index = load_ledger_index()
    scanned_this_run = 0
    run_findings = []
    while cursor < len(tasks) and scanned_this_run < args.batch_limit:
        item = tasks[cursor]
        number = int(item["pr"])
        label = str(item.get("range") or "historical")
        planned_sha = str(item.get("head_sha") or "")
        print(f"Historical batch {label}: checking PR #{number} ({cursor + 1}/{len(tasks)}).", flush=True)

        try:
            current = json.loads(gh([
                "pr", "view", str(number), "--repo", REPO, "--json",
                "title,body,author,headRefOid,baseRefName,headRefName,url,state,mergedAt"
            ]))
        except RateLimited:
            raise
        except Exception as exc:
            raise RuntimeError(
                f"PR #{number}: metadata unavailable; leaving this item queued for retry: {str(exc)[:300]}"
            ) from exc

        sha = str(current.get("headRefOid") or planned_sha)
        key = f"{number}:{sha}"
        checked = is_currently_checked(number, sha, state, ledger_index)
        if checked:
            cursor += 1
            state["batch_queue_cursor"] = cursor
            scanned_this_run += 1
            save_state(state)
            print(f"PR #{number}: skipped; current head already has a {checked} review.", flush=True)
            continue

        try:
            diff = gh(["pr", "diff", str(number), "--repo", REPO])
        except RateLimited:
            raise
        except Exception as exc:
            raise RuntimeError(
                f"PR #{number}: diff unavailable; leaving this item queued for retry: {str(exc)[:300]}"
            ) from exc

        findings = scan(diff)
        high = [finding for finding in findings if finding.get("severity") == "high"]
        medium = [finding for finding in findings if finding.get("severity") == "medium"]
        provisional = "do-not-merge" if high else ("notes" if medium else "clean")
        author = current.get("author") or {}
        if isinstance(author, str):
            author = {"login": author}
        merged = bool(current.get("mergedAt"))
        pr_state = str(current.get("state") or item.get("state") or "unknown").lower()

        safe_findings = []
        for finding in findings:
            clean = dict(finding)
            label_text = str(clean.get("pattern", "")).lower()
            if any(word in label_text for word in ("credential", "password", "secret", "token")):
                clean["match"] = "[evidence redacted; inspect the added line privately]"
            safe_findings.append(clean)

        result = {
            "pr": number,
            "head_sha": sha,
            "range": label,
            "state": pr_state,
            "merged": merged,
            "title": current.get("title", ""),
            "url": current.get("url", ""),
            "author": author.get("login", ""),
            "provisional_verdict": provisional,
            "scope": "historical static pattern scan of added diff lines; no code executed; not a full review",
            "findings": safe_findings
        }
        category_dir = BATCH_RESULTS_DIR / provisional
        category_dir.mkdir(parents=True, exist_ok=True)
        (category_dir / f"{number}.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8"
        )
        if high or medium:
            run_findings.append(result)

        # Every historical pass is explicitly recorded as scan-only in the matching
        # verdict folder; detailed heuristic matches remain in the per-run artifact.
        record = {
            "source": SOURCE,
            "pr": number,
            "head_sha": sha,
            "reviewer": SOURCE + "/automated",
            "date": datetime.now(timezone.utc).date().isoformat(),
            "scope": f"historical {label} static scan; no code executed; heuristic only, not a full review",
            "verdict": "scan-only",
            "findings": [],
            "read_by_human": False,
            "commented_on_github": False,
            "provisional_verdict": provisional,
            "heuristic_signal_counts": {"high": len(high), "medium": len(medium)},
            "pr_title": current.get("title", ""),
            "author": author.get("login", ""),
            "pr_url": current.get("url", ""),
            "pr_state": pr_state,
            "merged": merged,
            "historical_batch": label,
            "historical_scan_at": now()
        }
        existing_paths = []
        for folder in ("clean", "notes", "do-not-merge", "scan-only", "not-reviewed", "in-progress"):
            candidate = LEDGER_REVIEWS_DIR / folder / f"{number}.json"
            if candidate.exists():
                existing_paths.append(candidate)
        flat_candidate = LEDGER_REVIEWS_DIR / f"{number}.json"
        if flat_candidate.exists():
            existing_paths.append(flat_candidate)

        if not existing_paths:
            scan_only_dir = LEDGER_REVIEWS_DIR / "scan-only"
            scan_only_dir.mkdir(parents=True, exist_ok=True)
            (scan_only_dir / f"{number}.json").write_text(
                json.dumps(record, indent=2) + "\n", encoding="utf-8"
            )
        else:
            # Never overwrite a prior human or already-published review.
            print(
                f"PR #{number}: preserving existing ledger record(s); detailed rerun remains in the Actions artifact.",
                flush=True
            )

        state.setdefault("reviewed", {})[key] = {
            "verdict": "scan-only",
            "at": now(),
            "batch": label,
            "provisional_verdict": provisional,
            "high_signal_count": len(high),
            "medium_signal_count": len(medium)
        }
        stats = current_batch_stats(state, label)
        if stats:
            stats["scanned"] = int(stats.get("scanned", 0)) + 1
            if high:
                stats["high_alerts"] = int(stats.get("high_alerts", 0)) + 1
            elif medium:
                stats["medium_signal_prs"] = int(stats.get("medium_signal_prs", 0)) + 1
        cursor += 1
        state["batch_queue_cursor"] = cursor
        scanned_this_run += 1
        if scanned_this_run % 10 == 0:
            save_state(state)
        print(
            f"PR #{number}: {provisional}; stored in reviews/scan-only; "
            f"{len(high)} high and {len(medium)} medium heuristic signal(s).",
            flush=True
        )

    BATCH_REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    BATCH_REPORT_FILE.write_text(
        json.dumps({
            "generated_at": now(),
            "cursor_start": max(0, cursor - scanned_this_run),
            "cursor_end": cursor,
            "scanned_this_run": scanned_this_run,
            "flagged_prs": run_findings,
            "by_verdict": {
                verdict: [item for item in run_findings if item.get("provisional_verdict") == verdict]
                for verdict in ("do-not-merge", "notes", "clean")
            }
        }, indent=2) + "\n",
        encoding="utf-8"
    )
    state["batch_queue_cursor"] = cursor
    save_state(state)
    print(
        f"Historical batch progress: cursor {cursor}/{len(tasks)}; "
        f"processed {scanned_this_run} PRs this run; high-signal PRs {len(run_findings)}.",
        flush=True
    )
    if cursor >= len(tasks):
        state.setdefault("historical_batch", {})["completed_at"] = now()
        save_state(state)
        print("All requested historical PR ranges have been scanned.", flush=True)
    return True



def scan(diff):
    out, seen, path, line_no = [], set(), "", 0
    for line in diff.splitlines():
        if line.startswith("+++ b/"): path, line_no = line[6:], 0; continue
        if line.startswith("@@"):
            m = re.search(r"\+(\d+)", line); line_no = int(m.group(1))-1 if m else line_no; continue
        if line.startswith("+") and not line.startswith("+++"):
            line_no += 1; code = line[1:]; safe = bool(SAFE_PATH.search(path) or SAFE_WORDS.search(code))
            for severity, rules in (("high",HIGH),("medium",MEDIUM),("low",LOW)):
                for pattern, label in rules:
                    if not re.search(pattern, code, re.I): continue
                    if safe and severity != "high": continue
                    key=(path,line_no,label)
                    if key not in seen:
                        seen.add(key); out.append({"file":path,"line":line_no,"pattern":label,"match":code.strip()[:220],"severity":severity})
        elif line and not line.startswith("-"): line_no += 1
    return out

def norm(s): return " ".join(re.sub(r"[^a-z0-9]+"," ",(s or "").lower()).split())

def duplicate_checks(prs):
    results={}
    for p in prs:
        a=norm(p.get("title")); author=(p.get("author") or {}).get("login")
        found=[]
        for q in prs:
            if q["number"] == p["number"]: continue
            b=norm(q.get("title")); ratio=difflib.SequenceMatcher(None,a,b).ratio() if a and b else 0
            same_body=bool(norm(p.get("body")) and norm(q.get("body")) and
                difflib.SequenceMatcher(None,norm(p.get("body")),norm(q.get("body"))).ratio() >= .94)
            same_author=author and author==(q.get("author") or {}).get("login")
            if (ratio >= .92 or same_body):
                found.append({"file":"","line":0,"pattern":"Possible duplicate PR","match":f"Similar to PR #{q['number']}: {q.get('title','')[:120]} ({ratio:.0%} title similarity)","severity":"medium","related_pr":q["number"]})
            elif same_author and ratio >= .78:
                found.append({"file":"","line":0,"pattern":"Repeated PR by same author","match":f"Similar to PR #{q['number']} ({ratio:.0%} title similarity)","severity":"low","related_pr":q["number"]})
        results[p["number"]]=found
    return results

def signature_id(finding):
    material = norm(finding.get("pattern", "")) + "|" + norm(finding.get("match", ""))
    return hashlib.sha256(material.encode()).hexdigest() if material.strip("|") else ""

def seed_historical_signatures(state):
    history = state.setdefault("malicious_signatures", {})
    for path in OUT.glob("*.json"):
        if path.name == QUEUE.name: continue
        try:
            review = json.loads(path.read_text())
            for finding in review.get("detailed_findings", []):
                if finding.get("severity") != "high": continue
                sig = signature_id(finding)
                if sig and sig not in history:
                    history[sig] = {"first_pr": review.get("pr"), "pattern": finding.get("pattern", "High-severity indicator"), "first_seen": review.get("created_at", now()), "occurrences": 1}
        except (OSError, ValueError, TypeError):
            continue

def learn_from_previous(findings, state, pr_number):
    history = state.setdefault("malicious_signatures", {})
    additions = []
    for finding in list(findings):
        if finding.get("severity") != "high": continue
        sig = signature_id(finding)
        if not sig: continue
        previous = history.get(sig)
        if previous and previous.get("first_pr") != pr_number:
            additions.append({"file": finding.get("file", ""), "line": finding.get("line", 0),
                "pattern": "Previously detected malicious-code signature",
                "match": f"Same high-severity indicator previously detected in PR #{previous.get('first_pr')}: {previous.get('pattern', finding.get('pattern', ''))}; recurring code signature",
                "severity": "high", "related_pr": previous.get("first_pr")})
            previous["occurrences"] = int(previous.get("occurrences", 1)) + 1
            previous["last_seen"] = now()
        else:
            history.setdefault(sig, {"first_pr": pr_number, "pattern": finding.get("pattern", "High-severity indicator"), "first_seen": now(), "occurrences": 1})
    findings.extend(additions)
    return findings

def fingerprint(diff):
    added=[norm(x[1:]) for x in diff.splitlines() if x.startswith("+") and not x.startswith("+++")]
    return hashlib.sha256("\n".join(x for x in added if x).encode()).hexdigest() if added else ""


def load_state(path):
    """Load monitor state and repair the historical literal-\\n suffix bug."""
    if not path.exists():
        return {"reviewed": {}, "pending": []}

    raw = path.read_text(encoding="utf-8")
    try:
        state = json.loads(raw)
    except json.JSONDecodeError as original_error:
        repaired = raw.rstrip()
        removed = 0
        while repaired.endswith("\\n"):
            repaired = repaired[:-2]
            removed += 1
        if not removed:
            raise ValueError(f"Invalid monitor state JSON in {path}: {original_error}") from original_error
        try:
            state = json.loads(repaired)
        except json.JSONDecodeError as repair_error:
            raise ValueError(f"Could not repair monitor state JSON in {path}: {repair_error}") from repair_error
        path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        print(f"Recovered monitor state by removing {removed} literal \\\\n suffix(es).", flush=True)

    if not isinstance(state, dict):
        raise ValueError(f"Monitor state in {path} must be a JSON object.")
    if not isinstance(state.get("reviewed"), dict):
        state["reviewed"] = {}
    if not isinstance(state.get("pending"), list):
        state["pending"] = []
    return state

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--daemon", action="store_true")
    ap.add_argument("--interval", type=int, default=900)
    ap.add_argument("--since-pr", type=int, default=0)
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--seed-ranges", default="", help="Seed historical PR batches, e.g. 1000-3000,3001-6999,7000-9000")
    ap.add_argument("--batch-limit", type=int, default=100, help="Maximum historical PR diffs to scan in one workflow run")
    ap.add_argument("--validate-only", action="store_true")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    if args.validate_only:
        for path in OUT.glob("*.json"):
            if path.name == QUEUE.name:
                continue
            try:
                data = json.loads(path.read_text())
                if data.get("source") != SOURCE or data.get("verdict") not in ("notes", "do-not-merge"):
                    return 1
            except Exception:
                return 1
        return 0

    state = load_state(STATE)
    state.setdefault("reviewed", {})
    state.setdefault("pending", [])
    seed_historical_signatures(state)

    try:
        if args.seed_ranges:
            seed_historical_batches(state, args.seed_ranges)
        if run_historical_batch(args, state):
            return 0
        prs = get_prs(args.limit)
        dupes = duplicate_checks(prs)
        by_number = {p["number"]: p for p in prs}

        pending = []
        for item in state["pending"]:
            if not isinstance(item, dict) or not item.get("pr") or not item.get("head_sha"):
                continue
            live = by_number.get(item["pr"])
            if live and live.get("headRefOid", "") == item["head_sha"]:
                pending.append(item)
        pending_keys = {(x["pr"], x["head_sha"]) for x in pending}

        for p in sorted(prs, key=lambda x: x["number"]):
            n, sha = p["number"], p.get("headRefOid", "")
            key = f"{n}:{sha}"
            if n > args.since_pr and (n, sha) not in pending_keys and key not in state["reviewed"]:
                pending.append({"pr": n, "head_sha": sha})
                pending_keys.add((n, sha))

        print(f"Fetched {len(prs)} open PRs; pending {len(pending)}.", flush=True)
        # Consume clean scans in the same run. Stop at the first actionable finding so the
        # workflow can post exactly one COMMENT and preserve fair, ordered retries.
        while pending:
            item = pending[0]
            p = by_number[item["pr"]]
            n, sha = p["number"], item["head_sha"]
            key = f"{n}:{sha}"
            print(f"Analyzing PR #{n}: {p.get('title', '')}", flush=True)
            diff = gh(["pr", "diff", str(n), "--repo", REPO])
            findings = learn_from_previous(scan(diff) + dupes.get(n, []), state, n)
            if len((p.get("title") or "").strip()) < 8 or (
                not (p.get("body") or "").strip() and not any(x.startswith("+") for x in diff.splitlines())
            ):
                findings.append({
                    "file": "", "line": 0, "pattern": "Low-quality PR metadata",
                    "match": "Very short title or empty description with no substantive additions",
                    "severity": "low"
                })

            high = [x for x in findings if x["severity"] == "high"]
            verdict = "do-not-merge" if high else ("notes" if findings else "clean")
            if verdict == "clean":
                state["reviewed"][key] = {"verdict": "scan-only", "at": now()}
                pending.pop(0)
                state["pending"] = pending
                STATE.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
                print(f"PR #{n}: scan-only; no approval or public comment.", flush=True)
                continue

            additions = sum(x.startswith("+") and not x.startswith("+++") for x in diff.splitlines())
            review = {
                "source": SOURCE, "pr": n, "head_sha": sha, "reviewer": SOURCE + "/automated",
                "date": datetime.now(timezone.utc).date().isoformat(), "created_at": now(),
                "scope": "heuristic static analysis of added diff lines and open-PR metadata; no code executed",
                "verdict": verdict,
                "findings": [f"#{x['file']}:{x['line']} - {x['pattern']} - {x['match']}" for x in findings],
                "detailed_findings": findings, "read_by_human": False, "commented_on_github": False,
                "review_submitted": False, "publication_status": "pending_github_comment",
                "pr_title": p.get("title", ""), "pr_url": p.get("url", ""),
                "author": (p.get("author") or {}).get("login", ""),
                "base_branch": p.get("baseRefName", ""), "head_branch": p.get("headRefName", ""),
                "additions": additions, "patch_fingerprint": fingerprint(diff)
            }
            (OUT / f"{n}.json").write_text(json.dumps(review, indent=2) + "\n", encoding="utf-8")
            state["pending"] = pending
            STATE.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
            QUEUE.write_text(json.dumps({"source": SOURCE, "prs": [n]}, indent=2) + "\n", encoding="utf-8")
            print(f"PR #{n}: {verdict}; queued for a GitHub COMMENT. Not public until posted.", flush=True)
            return 0

        state["pending"] = []
        STATE.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        QUEUE.write_text(json.dumps({"source": SOURCE, "prs": []}, indent=2) + "\n", encoding="utf-8")
        print("No actionable findings in the current PR batch.", flush=True)
        return 0

    except RateLimited as exc:
        print(f"RATE LIMITED; pending PR state preserved for the next scheduled run: {exc}", flush=True)
        STATE.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", flush=True)
        STATE.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
        return 1

if __name__ == "__main__":
    sys.exit(main())

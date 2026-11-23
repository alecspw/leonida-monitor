#!/usr/bin/env python3
"""Heuristic static PR monitor. Never executes contributor code."""
import argparse, difflib, hashlib, json, os, re, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

REPO = "ItsNotRexed/Leonida"
STATE = Path(os.getenv("MONITOR_STATE_FILE", "monitor_state.json"))
OUT = Path(os.getenv("MONITOR_REVIEWS_DIR", "reviews"))
QUEUE = OUT / "comment_queue.json"
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
 (r"\b(?:eval|exec|compile)\s*\(", "Dynamic code execution"),
 (r"\b(?:subprocess\.(?:run|Popen|call)|os\.system)\s*\(", "OS command execution"),
 (r"\b(?:requests\.(?:get|post)|urlopen|httpx\.(?:get|post))\s*\(", "Network request"),
 (r"\b(?:ctypes|cffi)\b|\bLoadLibrary(?:Ex)?\s*\(", "Native library loading"),
 (r"\b(?:base64|binascii)\.(?:b64decode|unhexlify)\s*\(", "Encoded payload handling"),
 (r"\b(?:reg\s+add|winreg\.SetValue|schtasks)\b", "Persistence/registry operation"),
 (r"\b(?:shell\s*=\s*True|--index-url|extra-index-url)\b", "Shell execution or package source override"),
 (r"\b(?:api[_-]?key|secret|access[_-]?token|password)\s*[:=]\s*['\"][^'\"]{12,}['\"]", "Possible hardcoded secret"),
]
LOW = [(r"\b(?:shader|executable|dump|decrypt|game_data)\b", "Sensitive terminology"),
       (r"\b(?:TODO|FIXME|HACK)\b", "Unfinished-work marker")]
SAFE_PATH = re.compile(r"(^|/)(tests?|docs?|examples?|fixtures?)(/|$)|\.(md|rst|txt)$", re.I)
SAFE_WORDS = re.compile(r"\b(mock|fixture|example|test case|not executed|placeholder)\b", re.I)

class RateLimited(Exception): pass

def now(): return datetime.now(timezone.utc).isoformat()

def gh(args, timeout=45):
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

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--daemon", action="store_true")
    ap.add_argument("--interval", type=int, default=900)
    ap.add_argument("--since-pr", type=int, default=0)
    ap.add_argument("--limit", type=int, default=25)
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

    state = json.loads(STATE.read_text()) if STATE.exists() else {"reviewed": {}, "pending": []}
    state.setdefault("reviewed", {})
    state.setdefault("pending", [])
    seed_historical_signatures(state)

    try:
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

#!/usr/bin/env python3
"""
Jira Round-Robin Assigner (Server/DC & Cloud) - Single Run + JSON logging
- یک بار اجرا می‌شود و خارج می‌گردد (مناسب cron)
- Dry-run با DRY_RUN=true، برای اعمال واقعی DRY_RUN=false
- سازگار با Jira Server/DC (API v2: payload {"name": ...}) و Cloud (accountId)
- خروجی لاگ هر اجرا در قالب JSONL (هر اجرا یک خط JSON) ذخیره می‌شود.

ENV:
  JIRA_BASE_URL, JIRA_USER, (JIRA_API_TOKEN | JIRA_PASSWORD), JIRA_API_VERSION
  JQL, TEAM(JSON), SKIP(JSON), ROTATION_STATE_FILE, DRY_RUN(true/false)
  RATE_LIMIT_SLEEP, LOG_ERRORS(true/false)
  CIS_FIELD_NAME (اختیاری؛ پیش‌فرض: "NTA TPS CIs")
  LOG_JSON_PATH (اختیاری؛ پیش‌فرض: "assign_log.jsonl")
  TEXT_LOG_PATH (اختیاری؛ پیش‌فرض: "assign_stdout.log")
"""

import os
import sys
import json
import time
import requests
from collections import deque
from requests.auth import HTTPBasicAuth
import getpass
from datetime import datetime

# ===== Text log tee (write every print also to file) =====
TEXT_LOG_PATH = os.getenv("TEXT_LOG_PATH", "./assign_stdout.log")

import builtins

def _ensure_text_log_ready():
    try:
        base_dir = os.path.dirname(TEXT_LOG_PATH) or "."
        os.makedirs(base_dir, exist_ok=True)
        with open(TEXT_LOG_PATH, "a", encoding="utf-8"):
            pass
        return True
    except Exception as e:
        builtins.print(f"[WARN] Cannot prepare TEXT_LOG_PATH '{TEXT_LOG_PATH}': {e}")
        return False

_textlog_ok = _ensure_text_log_ready()
_orig_print = builtins.print

def _tee_print(*args, **kwargs):
    _orig_print(*args, **kwargs)  # console
    if not _textlog_ok:
        return
    try:
        kwargs2 = dict(kwargs)
        kwargs2.pop("file", None)  # avoid double 'file='
        with open(TEXT_LOG_PATH, "a", encoding="utf-8") as f:
            _orig_print(*args, file=f, **kwargs2)
    except Exception as e:
        _orig_print(f"[WARN] Failed to write TEXT_LOG_PATH '{TEXT_LOG_PATH}': {e}")

builtins.print = _tee_print

# ====== CONFIG ======
JIRA_BASE_URL = os.getenv("JIRA_BASE_URL", "https://your-domain.atlassian.net").rstrip("/")
JIRA_USER = os.getenv("JIRA_USER", "you@example.com")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")   # Cloud
JIRA_PASSWORD = os.getenv("JIRA_PASSWORD")     # Server/DC
JIRA_API_VERSION = os.getenv("JIRA_API_VERSION", "3")

JQL = os.getenv("JQL", 'project = "NTA TPS SM" AND issuetype = Incident AND status = "In Progress - 2" AND assignee IS EMPTY AND "NTA TPS CIs" in ("هوش تجاری (NTC-20200)","تحلیل ریسک و حسابرسی سیستمی (NTC-20199)","تبادل داده (NTC-20198)","مدیریت داده (NTC-18755)") ORDER BY created DESC')

def _load_json_env(name, default_str):
    try:
        return json.loads(os.getenv(name, default_str))
    except json.JSONDecodeError as e:
        raise SystemExit(f"{name} must be JSON. Error: {e}")

TEAM = _load_json_env("TEAM", '["ali","sara","mohsen","neda"]')          # list[str]
SKIP = set(_load_json_env("SKIP", '[]'))                                 # set[str]

ROTATION_STATE_FILE = os.getenv("ROTATION_STATE_FILE", "rotation_state.json")
DRY_RUN = os.getenv("DRY_RUN", "true").lower() == "true"
RATE_LIMIT_SLEEP = float(os.getenv("RATE_LIMIT_SLEEP", "0.6"))
LOG_ERRORS = os.getenv("LOG_ERRORS", "true").lower() == "true"

# JSON log file path
LOG_JSON_PATH = os.getenv("LOG_JSON_PATH", "assign_log.jsonl")

# ====== CIS-based routing config ======
CIS_FIELD_NAME = os.getenv("CIS_FIELD_NAME", "NTA TPS CIs")

# Exact value -> user
CIS_EXACT_MAP = {
    "سامانه جامع مبارزه با فرار مالیاتی (NTC-22916)": "p.rahimi",
    "درگاه جمع آوری عمومی (NTC-19257)": "a.rajabian",
}
# Any value IN set -> user (order of checks below matters)
CIS_IN_SET_MAP = {
    "a.fazlollahi": {
        "واکنش ذی نفع (NTC-19211)",
        "جزئیات رسیدگی (NTC-21923)",
    },
    "moha.mohammadi": {
        "مدیریت داده (NTC-18755)",
        "تبادل داده (NTC-20198)",
        "تحلیل ریسک و حسابرسی سیستمی (NTC-20199)",
        "هوش تجاری (NTC-20200)",
    },
}

# ====== AUTH ======
def build_auth():
    global JIRA_API_TOKEN, JIRA_PASSWORD, JIRA_USER
    if JIRA_API_TOKEN:
        print("[INFO] Using API Token authentication (Cloud).")
        return HTTPBasicAuth(JIRA_USER, JIRA_API_TOKEN)
    if not JIRA_PASSWORD:
        try:
            JIRA_PASSWORD = getpass.getpass(f"Jira password for {JIRA_USER}: ")
        except Exception:
            pass
    if JIRA_PASSWORD:
        print("[INFO] Using Basic Auth with username/password.")
        return HTTPBasicAuth(JIRA_USER, JIRA_PASSWORD)
    raise SystemExit("No credentials provided. Set JIRA_API_TOKEN or JIRA_PASSWORD (and JIRA_USER).")

AUTH = build_auth()

# ====== UTIL ======
def load_rotation_index():
    if os.path.exists(ROTATION_STATE_FILE):
        try:
            with open(ROTATION_STATE_FILE, "r") as f:
                data = json.load(f)
                return int(data.get("rotation_index", 0))
        except Exception:
            return 0
    return 0

def save_rotation_index(idx):
    with open(ROTATION_STATE_FILE, "w") as f:
        json.dump({"rotation_index": idx}, f, indent=2)

def next_assignees(team_list, skip_set, start_idx, n):
    if not team_list:
        return [], start_idx
    rr = deque(team_list)
    rr.rotate(-start_idx)
    out, steps = [], 0
    safeguard = max(10000, 5 * (len(team_list) + n))
    while len(out) < n and team_list:
        cand = rr[0]
        if cand not in skip_set:
            out.append(cand)
        rr.rotate(-1)
        steps += 1
        if steps > safeguard:
            raise RuntimeError("Too many steps in RR loop. Check team/skip lists.")
    new_idx = (start_idx + steps) % len(team_list) if team_list else 0
    return out, new_idx

def api_path(suffix):
    version = "2" if str(JIRA_API_VERSION).strip() == "2" else "3"
    return f"{JIRA_BASE_URL}/rest/api/{version}/{suffix}"

def jira_get(path, params=None):
    url = api_path(path)
    r = requests.get(url, params=params, auth=AUTH, headers={"Accept": "application/json"})
    if r.status_code == 401:
        raise SystemExit("Unauthorized (401). Check credentials/auth method.")
    r.raise_for_status()
    try:
        return r.json() if r.text else {}
    except ValueError:
        return {}

def jira_put_assign(issue_key, payload):
    url = api_path(f"issue/{issue_key}/assignee")
    r = requests.put(url, json=payload, auth=AUTH, headers={"Content-Type": "application/json"})
    if r.status_code not in (200, 204):
        raise RuntimeError(f"Failed to assign {issue_key}: {r.status_code} {r.text}")
    return True

def search_issues(jql, max_results=500, extra_fields=None):
    start_at = 0
    issues = []
    base_fields = ["summary", "priority", "assignee"]
    if extra_fields:
        base_fields.extend(extra_fields)
    fields_str = ",".join(base_fields)

    while True:
        data = jira_get("search", params={
            "jql": jql,
            "startAt": start_at,
            "maxResults": min(100, max_results - start_at),
            "fields": fields_str
        })
        batch = data.get("issues", []) if isinstance(data, dict) else []
        issues.extend(batch)
        total = data.get("total", 0) if isinstance(data, dict) else 0
        if start_at + len(batch) >= total or len(issues) >= max_results:
            break
        start_at += len(batch)
    return issues

# ----- Server/DC + Cloud compatible user resolution -----
def get_user_identifier(username_or_email):
    # Server/DC first (username=)
    try:
        data = jira_get("user/search", params={"username": username_or_email})
        if isinstance(data, list) and data:
            name = data[0].get("name") or data[0].get("key") or username_or_email
            return {"mode": "server", "name": name}
    except Exception:
        pass
    # Cloud/newer (query=)
    data = jira_get("user/search", params={"query": username_or_email})
    if isinstance(data, list) and data:
        acct = data[0].get("accountId")
        if acct:
            return {"mode": "cloud", "accountId": acct}
    raise RuntimeError(f"User not found: {username_or_email}")

def build_assign_payload(user_id):
    if user_id.get("mode") == "server" and user_id.get("name"):
        return {"name": user_id["name"]}           # Jira Server/DC
    if user_id.get("accountId"):
        return {"accountId": user_id["accountId"]} # Jira Cloud
    raise RuntimeError("Cannot build assign payload for user.")

# ====== CIS field resolving & routing ======
_CIS_FIELD_ID = None

def get_field_id_by_name(display_name):
    """Resolve field id like 'customfield_12345' by its display name."""
    global _CIS_FIELD_ID
    if _CIS_FIELD_ID:
        return _CIS_FIELD_ID
    all_fields = jira_get("field")
    if not isinstance(all_fields, list):
        raise RuntimeError("Unexpected response from /field")
    for f in all_fields:
        if str(f.get("name")) == display_name:
            _CIS_FIELD_ID = f.get("id")
            break
    if not _CIS_FIELD_ID:
        raise RuntimeError(f"Cannot find field id for '{display_name}'")
    return _CIS_FIELD_ID

def _extract_option_values(raw):
    """
    خروجی: لیستی از رشته‌ها (value) برای فیلد سفارشی.
    حالت‌ها: None / str / dict{"value"|"name"} / list[dict or str]
    """
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, dict):
        v = raw.get("value") or raw.get("name") or str(raw)
        return [v]
    if isinstance(raw, list):
        out = []
        for it in raw:
            if isinstance(it, dict):
                out.append(it.get("value") or it.get("name") or str(it))
            else:
                out.append(str(it))
        return out
    return [str(raw)]

def route_by_cis(fields, cis_field_id):
    """
    اگر نگاشت اجباری بخورد، نام کاربر مقصد را برمی‌گرداند؛ در غیر این صورت None.
    اولویت: exact ها سپس IN-set ها به ترتیبی که تعریف شده‌اند.
    """
    raw = fields.get(cis_field_id)
    values = set(_extract_option_values(raw))

    # Exact match
    for val, user in CIS_EXACT_MAP.items():
        if val in values:
            return user

    # IN-set buckets (order preserved)
    for user, allowed in CIS_IN_SET_MAP.items():
        if values & allowed:
            return user

    return None

# ====== Assignable resolution (preflight) ======
def resolve_assignable_user_for_issue(issue_key, hint):
    """
    روی همان issue از /user/assignable/search می‌پرسیم چه کاربری assignable است.
    hint می‌تواند username/email/displayname باشد.
    خروجی: {"mode":"server","name":...} یا {"accountId":...} یا None
    """
    variants = [
        {"issueKey": issue_key, "username": hint},  # DC قدیمی
        {"issueKey": issue_key, "query": hint},     # DC جدید/Cloud
    ]
    for params in variants:
        try:
            arr = jira_get("user/assignable/search", params=params)
            if not isinstance(arr, list) or not arr:
                continue
            u = arr[0]
            if u.get("accountId"):
                return {"accountId": u["accountId"]}
            name = u.get("name") or u.get("key")
            if name:
                return {"mode": "server", "name": name}
        except Exception:
            continue
    return None

def _append_json_log(record: dict, path: str):
    """Append a single JSON object as one line into a .jsonl file (create if not exists)."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

# ===== one run =====
def run_once():
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[{ts}] ===== Round-Robin pass (single run) =====")
    print("[INFO] JIRA_API_VERSION =", JIRA_API_VERSION)

    rotation_index = load_rotation_index()
    print("[INFO] Current rotation index:", rotation_index)

    # لاگِ این اجرا
    log_record = {
        "ts": ts,
        "jira_base_url": JIRA_BASE_URL,
        "api_version": str(JIRA_API_VERSION),
        "dry_run": DRY_RUN,
        "jql": JQL,
        "rotation_index_before": rotation_index,
        "cis_field_name": CIS_FIELD_NAME,
        "cis_field_id": None,
        "preview": [],   # list of {key, to, mode, priority, summary}
        "assigned": 0,
        "errors": 0,
        "issues_total": 0,
        "new_rotation": rotation_index,
        "error_messages": [],
    }

    # 1) resolve cis field id & fetch issues with that field
    cis_field_id = None
    try:
        cis_field_id = get_field_id_by_name(CIS_FIELD_NAME)
        log_record["cis_field_id"] = cis_field_id
        issues = search_issues(JQL, extra_fields=[cis_field_id])
    except Exception as e:
        warn = f"Could not resolve custom field '{CIS_FIELD_NAME}': {e}"
        print(f"[WARN] {warn}")
        log_record["error_messages"].append(warn)
        issues = search_issues(JQL)

    if not issues:
        print("[INFO] No unassigned incidents match the JQL.")
        log_record["issues_total"] = 0
        _append_json_log(log_record, LOG_JSON_PATH)
        return {"assigned": 0, "issues": 0, "new_rotation": rotation_index}

    log_record["issues_total"] = len(issues)

    # 2) split issues into forced vs rr-needed (by CIS)
    forced_pairs = []   # list of (issue, who_hint)
    rr_issues = []      # list of issue
    for issue in issues:
        fields = issue.get("fields", {})
        who_forced = None
        if cis_field_id:
            try:
                who_forced = route_by_cis(fields, cis_field_id)
            except Exception as e:
                msg = f"route_by_cis failed for {issue.get('key')}: {e}"
                print(f"[WARN] {msg}")
                log_record["error_messages"].append(msg)
        if who_forced:
            forced_pairs.append((issue, who_forced))
        else:
            rr_issues.append(issue)

    # 3) preflight: any forced assignee not actually assignable? push to RR
    still_forced = []
    for issue, who in forced_pairs:
        ident = resolve_assignable_user_for_issue(issue["key"], who)
        if ident is None:
            msg = f"User hint '{who}' not assignable for {issue['key']} — moving to RR."
            print(f"[WARN] {msg}")
            log_record["error_messages"].append(msg)
            rr_issues.append(issue)
        else:
            still_forced.append((issue, who, ident))
    forced_pairs = still_forced

    # 4) compute RR assignees only for rr_issues
    effective_team = [m for m in TEAM if m not in SKIP]
    if rr_issues and not effective_team:
        msg = "RR is needed but effective TEAM is empty (all skipped?)."
        print(f"[WARN] {msg}")
        log_record["error_messages"].append(msg)
    try:
        assignees_rr, new_idx = next_assignees(effective_team, SKIP, rotation_index, len(rr_issues))
    except RuntimeError as e:
        msg = f"RR generation failed: {e}"
        print(f"[WARN] {msg}")
        log_record["error_messages"].append(msg)
        assignees_rr, new_idx = [], rotation_index

    # 5) preview (fill log preview too)
    print("--- PREVIEW ---")
    for issue, who, _ident in forced_pairs:
        f = issue.get("fields", {})
        pr = (f.get("priority") or {}).get("name")
        summ = f.get("summary")
        print(f"{issue.get('key')} -> {who} [FORCED] | {pr} | {summ}")
        log_record["preview"].append({
            "key": issue.get("key"),
            "to": who,
            "mode": "FORCED",
            "priority": pr,
            "summary": summ,
        })
    for issue, who in zip(rr_issues, assignees_rr):
        f = issue.get("fields", {})
        pr = (f.get("priority") or {}).get("name")
        summ = f.get("summary")
        print(f"{issue.get('key')} -> {who} [RR] | {pr} | {summ}")
        log_record["preview"].append({
            "key": issue.get("key"),
            "to": who,
            "mode": "RR",
            "priority": pr,
            "summary": summ,
        })

    # DRY-RUN
    if DRY_RUN:
        print("[INFO] Dry-run enabled. No changes applied.")
        print("[INFO] Next rotation index would be:", new_idx)
        log_record["new_rotation"] = new_idx
        _append_json_log(log_record, LOG_JSON_PATH)
        return {"assigned": 0, "issues": len(issues), "new_rotation": new_idx}

    # 6) commit
    ok, err = 0, 0

    # forced first (ident already resolved as assignable)
    for issue, who, ident in forced_pairs:
        try:
            payload = build_assign_payload(ident)
            jira_put_assign(issue["key"], payload)
            print(f"[OK] Assigned {issue['key']} to {who} [FORCED]")
            ok += 1
            time.sleep(RATE_LIMIT_SLEEP)
        except Exception as e:
            msg = f"{issue.get('key')} -> {who} [FORCED] failed: {e}"
            print(f"[ERR] {msg}")
            log_record["error_messages"].append(msg)
            err += 1

    # then RR ones (resolve per-issue assignable)
    for issue, who in zip(rr_issues, assignees_rr):
        ident = resolve_assignable_user_for_issue(issue["key"], who)
        if not ident:
            msg = f"User hint '{who}' not assignable for {issue['key']} — skipping."
            print(f"[WARN] {msg}")
            log_record["error_messages"].append(msg)
            err += 1
            continue
        try:
            payload = build_assign_payload(ident)
            jira_put_assign(issue["key"], payload)
            print(f"[OK] Assigned {issue['key']} to {who} [RR]")
            ok += 1
            time.sleep(RATE_LIMIT_SLEEP)
        except Exception as e:
            msg = f"{issue.get('key')} -> {who} [RR] failed: {e}"
            print(f"[ERR] {msg}")
            log_record["error_messages"].append(msg)
            err += 1

    # persist rotation only for RR path
    save_rotation_index(new_idx)
    print("[INFO] Commit done. New rotation index:", new_idx)

    # fill log counts and write
    log_record["assigned"] = ok
    log_record["errors"] = err
    log_record["new_rotation"] = new_idx
    _append_json_log(log_record, LOG_JSON_PATH)

    return {"assigned": ok, "errors": err, "issues": len(issues), "new_rotation": new_idx}

# ===== entry point (single run) =====
if __name__ == "__main__":
    try:
        stats = run_once()
        if stats:
            print(f"[INFO] Stats: {stats}")
        sys.exit(0)
    except Exception as e:
        if LOG_ERRORS:
            print(f"[FATAL] Unexpected error: {e}")
        try:
            _append_json_log({
                "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "fatal": True,
                "error": str(e),
            }, LOG_JSON_PATH)
        except Exception:
            pass
        sys.exit(1)

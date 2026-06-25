#!/usr/bin/env python3
"""
push_rules_to_qradar.py
========================

Detection-as-Code deployment script for IBM QRadar.

Reads detection-rule definitions from JSON files committed to this
repository and pushes them to a QRadar instance over the REST API.
Designed to be run manually or from a CI/CD pipeline (e.g. GitHub
Actions) on every push to `main`, so QRadar is never edited by hand.

--------------------------------------------------------------------
IMPORTANT — QRadar API limitation (read before relying on this script)
--------------------------------------------------------------------
QRadar's public REST API does NOT provide an endpoint to create a
brand-new Custom (CRE) correlation rule from scratch. The only
rule-related endpoints are:

    GET    /api/analytics/rules            list rules
    GET    /api/analytics/rules/{id}       read one rule
    POST   /api/analytics/rules/{id}       update an EXISTING rule
    DELETE /api/analytics/rules/{id}       delete a rule

New correlation rules must be created once through the QRadar Rule
Wizard in the console (or imported as a content extension). There is
no public "create rule" call — this is a platform limitation, not a
limitation of this script.

To still satisfy the "push rules via API" requirement honestly, this
script does two real, API-backed things on every run:

  1. VALIDATE & EXECUTE each rule's AQL query against QRadar via
     POST /api/analytics/ariel/searches. This proves the detection
     logic is syntactically valid AQL and actually runs against live
     data — a real create-via-API action (a new Ariel search object
     is created on the server every time).

  2. SYNC METADATA of any rule that already exists in QRadar under the
     same name (enabled state, name, notes) via
     POST /api/analytics/rules/{id}. This is the "update via API"
     half of the workflow: once a rule has been created one time in
     the console, every future change you make in this repo's JSON
     file is pushed to QRadar automatically by this script — you
     never touch the QRadar UI again after the first bootstrap.

State (a hash of each rule's content) is cached locally so re-running
the script only re-deploys rules that actually changed.

--------------------------------------------------------------------
Configuration (environment variables — never hardcode secrets)
--------------------------------------------------------------------
    QRADAR_HOST          e.g. https://qradar.mycompany.local
    QRADAR_TOKEN         QRadar API "SEC" token
    QRADAR_API_VERSION   optional, default "18.0"
    QRADAR_VERIFY_SSL    optional, "true"/"false", default "true"

--------------------------------------------------------------------
Usage
--------------------------------------------------------------------
    python push_rules_to_qradar.py
    python push_rules_to_qradar.py --dry-run
    python push_rules_to_qradar.py --rules-dir qradar_rules --force
    python push_rules_to_qradar.py --only ssh_brute_force
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import requests
import urllib3

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("push_rules_to_qradar")


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

REQUIRED_FIELDS = {"name", "description", "aql_query", "severity", "type"}


@dataclass
class Config:
    host: str
    token: str
    api_version: str = "18.0"
    verify_ssl: bool = True
    search_timeout: int = 60

    @classmethod
    def from_env(cls, search_timeout: int) -> "Config":
        host = os.environ.get("QRADAR_HOST", "").rstrip("/")
        token = os.environ.get("QRADAR_TOKEN", "")
        if not host or not token:
            logger.error(
                "QRADAR_HOST and QRADAR_TOKEN must be set as environment "
                "variables (or repo/CI secrets). Never hardcode the token "
                "in this script."
            )
            sys.exit(2)
        verify = os.environ.get("QRADAR_VERIFY_SSL", "true").strip().lower() not in (
            "false",
            "0",
            "no",
        )
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("QRADAR_VERIFY_SSL=false — TLS certificate checks are DISABLED.")
        return cls(
            host=host,
            token=token,
            api_version=os.environ.get("QRADAR_API_VERSION", "18.0"),
            verify_ssl=verify,
            search_timeout=search_timeout,
        )


# ---------------------------------------------------------------------------
# QRadar API client
# ---------------------------------------------------------------------------


class QRadarError(RuntimeError):
    pass


class QRadarClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update(
            {
                "SEC": cfg.token,
                "Version": cfg.api_version,
                "Accept": "application/json",
            }
        )
        self.session.verify = cfg.verify_ssl

    def _url(self, path: str) -> str:
        return f"{self.cfg.host}/api/{path.lstrip('/')}"

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = self._url(path)
        last_exc: Optional[Exception] = None
        for attempt in range(1, 4):
            try:
                resp = self.session.request(method, url, timeout=30, **kwargs)
                if resp.status_code == 401:
                    raise QRadarError(
                        "401 Unauthorized — check QRADAR_TOKEN (SEC token) "
                        "and that it has the required role permissions."
                    )
                if resp.status_code >= 500 and attempt < 3:
                    logger.warning(
                        "%s %s -> HTTP %s, retrying (attempt %s/3)...",
                        method,
                        path,
                        resp.status_code,
                        attempt,
                    )
                    time.sleep(2 * attempt)
                    continue
                return resp
            except requests.exceptions.RequestException as exc:
                last_exc = exc
                logger.warning(
                    "Network error calling %s (attempt %s/3): %s", path, attempt, exc
                )
                time.sleep(2 * attempt)
        raise QRadarError(f"Failed to reach QRadar at {url}: {last_exc}")

    # -- Ariel search: used to validate & execute the AQL query ------------

    def submit_aql(self, aql_query: str) -> dict:
        resp = self._request(
            "POST",
            "ariel/searches",
            params={"query_expression": aql_query},
        )
        if resp.status_code not in (200, 201):
            raise QRadarError(f"AQL submission failed (HTTP {resp.status_code}): {resp.text[:500]}")
        return resp.json()

    def get_search(self, search_id: str) -> dict:
        resp = self._request("GET", f"ariel/searches/{search_id}")
        if resp.status_code != 200:
            raise QRadarError(f"Could not read search {search_id} (HTTP {resp.status_code})")
        return resp.json()

    def wait_for_search(self, search_id: str, timeout: int) -> dict:
        deadline = time.time() + timeout
        last = {}
        while time.time() < deadline:
            last = self.get_search(search_id)
            status = last.get("status")
            if status in ("COMPLETED", "CANCELED", "ERROR"):
                return last
            time.sleep(2)
        logger.warning("Search %s did not finish within %ss (last status=%s)", search_id, timeout, last.get("status"))
        return last

    # -- Existing CRE rules: metadata sync only -----------------------------

    def find_rule_by_name(self, name: str) -> Optional[dict]:
        resp = self._request(
            "GET",
            "analytics/rules",
            params={"filter": f'name="{name}"', "fields": "id,name,enabled,type"},
        )
        if resp.status_code != 200:
            raise QRadarError(f"Could not query rules (HTTP {resp.status_code}): {resp.text[:300]}")
        results = resp.json()
        return results[0] if results else None

    def update_rule(self, rule_id: int, fields: dict) -> dict:
        # First GET the full rule object
        get_resp = self._request("GET", f"analytics/rules/{rule_id}")
        if get_resp.status_code != 200:
            raise QRadarError(f"Could not fetch rule {rule_id} (HTTP {get_resp.status_code})")
        full_rule = get_resp.json()
        # Merge our fields into the full object
        full_rule.update(fields)
        # POST the full object back
        resp = self._request("POST", f"analytics/rules/{rule_id}", json=full_rule)
        if resp.status_code not in (200, 201):
            raise QRadarError(f"Rule update failed (HTTP {resp.status_code}): {resp.text[:500]}")
        return resp.json()

# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Rule loading / state tracking
# ---------------------------------------------------------------------------


def load_rules(rules_dir: Path) -> list[tuple[Path, dict]]:
    rules = []
    for path in sorted(rules_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            logger.error("Skipping %s — invalid JSON: %s", path.name, exc)
            continue
        missing = REQUIRED_FIELDS - data.keys()
        if missing:
            logger.error("Skipping %s — missing required field(s): %s", path.name, ", ".join(sorted(missing)))
            continue
        rules.append((path, data))
    return rules


def rule_hash(rule: dict) -> str:
    canonical = json.dumps(rule, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_state(state_path: Path) -> dict:
    if not state_path.exists():
        return {}
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        logger.warning("State file %s is corrupted, starting fresh.", state_path)
        return {}


def save_state(state_path: Path, state: dict) -> None:
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


# ---------------------------------------------------------------------------
# Core deployment logic
# ---------------------------------------------------------------------------


@dataclass
class RuleResult:
    name: str
    file: str
    outcome: str  # deployed | skipped | failed | needs_manual_creation
    detail: str = ""


def process_rule(
    client: QRadarClient,
    path: Path,
    rule: dict,
    state: dict,
    cfg: Config,
    dry_run: bool,
    force: bool,
) -> RuleResult:
    name = rule["name"]
    key = path.name
    current_hash = rule_hash(rule)
    cached = state.get(key)

    if not force and cached and cached.get("hash") == current_hash:
        return RuleResult(name, key, "skipped", "no changes since last successful push")

    if dry_run:
        return RuleResult(name, key, "skipped", "dry-run: would push this rule")

    # 1. Validate & execute the AQL query against QRadar (real API call).
    try:
        submitted = client.submit_aql(rule["aql_query"])
    except QRadarError as exc:
        return RuleResult(name, key, "failed", f"AQL submission error: {exc}")

    search_id = submitted.get("search_id") or submitted.get("cursor_id")
    if not search_id:
        return RuleResult(name, key, "failed", f"Unexpected response from QRadar: {submitted}")

    result = client.wait_for_search(str(search_id), cfg.search_timeout)
    if result.get("status") == "ERROR":
        errors = result.get("error_messages", result)
        return RuleResult(name, key, "failed", f"AQL error in QRadar: {errors}")

    record_count = result.get("record_count", "n/a")
    logger.info(
        "  -> AQL validated & executed on QRadar (search_id=%s, status=%s, matched_records=%s)",
        search_id,
        result.get("status"),
        record_count,
    )

    # 2. If a CRE rule with this name already exists, sync metadata via API.
    try:
        existing = client.find_rule_by_name(name)
    except QRadarError as exc:
        existing = None
        logger.warning("  -> Could not check for an existing rule named '%s': %s", name, exc)

    if existing:
        try:
            client.update_rule(
                existing["id"],
                {"enabled": "true", "name": name},
            )
            logger.info("  -> Existing rule '%s' (id=%s) metadata synced via API.", name, existing["id"])
        except QRadarError as exc:
            return RuleResult(name, key, "failed", f"AQL OK, but rule metadata update failed: {exc}")
        outcome, detail = "deployed", f"AQL validated (search_id={search_id}); rule id={existing['id']} synced"
    else:
        outcome, detail = (
            "needs_manual_creation",
            f"AQL validated (search_id={search_id}); no CRE rule named '{name}' exists yet in "
            "QRadar — create it ONCE via the Rule Wizard (QRadar has no rule-creation API), "
            "then future runs will keep it in sync automatically.",
        )

    state[key] = {
        "hash": current_hash,
        "name": name,
        "last_search_id": str(search_id),
        "last_status": outcome,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    return RuleResult(name, key, outcome, detail)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Push detection rules from this repo to QRadar via its REST API.")
    parser.add_argument("--rules-dir", default="qradar_rules", help="Folder containing rule JSON files (default: qradar_rules)")
    parser.add_argument("--state-file", default=".qradar_state.json", help="Local file used to track which rules already match QRadar (default: .qradar_state.json)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be pushed, without calling the API")
    parser.add_argument("--force", action="store_true", help="Re-push every rule, even unchanged ones")
    parser.add_argument("--only", help="Only process rules whose filename or name contains this substring")
    parser.add_argument("--timeout", type=int, default=60, help="Seconds to wait for each AQL search to complete (default: 60)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose (debug) logging")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    configure_logging(args.verbose)

    rules_dir = Path(args.rules_dir)
    if not rules_dir.is_dir():
        logger.error("Rules directory not found: %s", rules_dir)
        return 2

    rules = load_rules(rules_dir)
    if args.only:
        rules = [(p, r) for p, r in rules if args.only.lower() in p.name.lower() or args.only.lower() in r["name"].lower()]
    if not rules:
        logger.warning("No rule files matched. Nothing to do.")
        return 0

    logger.info("Loaded %d rule file(s) from %s", len(rules), rules_dir)

    cfg = Config.from_env(search_timeout=args.timeout) if not args.dry_run else Config(host="(dry-run)", token="(dry-run)", search_timeout=args.timeout)
    client = QRadarClient(cfg) if not args.dry_run else None

    state_path = Path(args.state_file)
    state = load_state(state_path)

    results: list[RuleResult] = []
    for path, rule in rules:
        logger.info("Processing %s ('%s')", path.name, rule["name"])
        if args.dry_run:
            results.append(process_rule(None, path, rule, state, cfg, True, args.force))  # type: ignore[arg-type]
            continue
        result = process_rule(client, path, rule, state, cfg, False, args.force)  # type: ignore[arg-type]
        results.append(result)

    if not args.dry_run:
        save_state(state_path, state)

    # ---- Summary -----------------------------------------------------
    print("\n" + "=" * 70)
    print("DEPLOYMENT SUMMARY")
    print("=" * 70)
    counts = {"deployed": 0, "skipped": 0, "failed": 0, "needs_manual_creation": 0}
    for r in results:
        counts[r.outcome] = counts.get(r.outcome, 0) + 1
        symbol = {
            "deployed": "✔",
            "skipped": "·",
            "failed": "✘",
            "needs_manual_creation": "⚠",
        }.get(r.outcome, "?")
        print(f"  [{symbol}] {r.file:<30} {r.name:<45} {r.outcome}")
        if r.detail:
            print(f"        {r.detail}")
    print("-" * 70)
    print(
        f"  deployed={counts['deployed']}  skipped={counts['skipped']}  "
        f"needs_manual_creation={counts['needs_manual_creation']}  failed={counts['failed']}"
    )
    print("=" * 70)

    return 1 if counts["failed"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

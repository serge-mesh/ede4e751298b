#!/usr/bin/env python3
"""Export open SonarQube Cloud issues to SARIF 2.1.0 for GitHub Code Scanning."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

SONARCLOUD_HOST = "sonarcloud.io"
SONARCLOUD_BASE_URL = f"https://{SONARCLOUD_HOST}"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "SonarQube Cloud"
HTTP_TIMEOUT_SECONDS = 30
MAX_PAGE_SIZE = 500
MAX_PAGES = 20
MAX_RULE_TAGS = 10

PROJECT_KEY_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PR_NUMBER_RE = re.compile(r"^[1-9][0-9]*$")

SEVERITY_RANK = {
    "INFO": 0,
    "MINOR": 1,
    "MAJOR": 2,
    "CRITICAL": 3,
    "BLOCKER": 4,
}

SARIF_LEVEL_BY_SEVERITY = {
    "BLOCKER": "error",
    "CRITICAL": "error",
    "MAJOR": "warning",
    "MINOR": "note",
    "INFO": "note",
}

SECURITY_SEVERITY_BY_SONAR = {
    "BLOCKER": "9.5",
    "CRITICAL": "8.0",
    "MAJOR": "5.5",
    "MINOR": "2.5",
    "INFO": "2.5",
}

TYPE_TAGS = {
    "VULNERABILITY": "security",
    "BUG": "bug",
    "CODE_SMELL": "code-smell",
}


@dataclass(frozen=True)
class SyncTarget:
    project_key: str
    kind: str  # "branch" or "pull_request"
    value: str
    ref: str
    sha: str


class SonarApiError(RuntimeError):
    """Raised when SonarQube Cloud returns an unexpected error."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def default_project_key(repository: str | None) -> str:
    if not repository or "/" not in repository:
        raise ValueError("Cannot derive SonarQube Cloud project key; pass --project-key")
    key = repository.replace("/", "_")
    return validate_project_key(key)


def validate_project_key(project_key: str) -> str:
    if not PROJECT_KEY_RE.fullmatch(project_key):
        raise ValueError(f"Invalid SonarQube Cloud project key: {project_key!r}")
    return project_key


def validate_branch_name(branch: str) -> str:
    if (
        not branch
        or branch.startswith(("/", "-"))
        or branch.endswith("/")
        or ".." in branch
        or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in branch)
    ):
        raise ValueError(f"Invalid branch name: {branch!r}")
    return branch


def validate_pr_number(pull_request: str) -> str:
    if not PR_NUMBER_RE.fullmatch(pull_request):
        raise ValueError(f"Invalid pull request number: {pull_request!r}")
    return pull_request


def validate_sha(sha: str) -> str:
    normalized = sha.strip().lower()
    if not SHA_RE.fullmatch(normalized):
        raise ValueError(f"Invalid commit SHA: {sha!r}")
    return normalized


def parse_check_run_url(
    details_url: str,
    head_sha: str,
    expected_project_key: str | None = None,
) -> SyncTarget | None:
    """Parse a SonarQube Cloud check-run details_url into a SyncTarget."""
    if not details_url:
        return None

    parsed = urllib.parse.urlparse(details_url)
    if parsed.scheme.lower() != "https" or parsed.netloc.lower() != SONARCLOUD_HOST:
        return None

    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
    project_ids = params.get("id")
    if not project_ids:
        return None
    project_key = validate_project_key(project_ids[0])
    if expected_project_key and project_key != expected_project_key:
        return None

    sha = validate_sha(head_sha)
    if "pullRequest" in params:
        pr_number = validate_pr_number(params["pullRequest"][0])
        return SyncTarget(
            project_key=project_key,
            kind="pull_request",
            value=pr_number,
            ref=f"refs/pull/{pr_number}/head",
            sha=sha,
        )
    if "branch" in params:
        branch = validate_branch_name(params["branch"][0])
        return SyncTarget(
            project_key=project_key,
            kind="branch",
            value=branch,
            ref=f"refs/heads/{branch}",
            sha=sha,
        )
    return None


def sonar_get_json(
    path: str,
    params: dict[str, str],
    token: str | None = None,
    base_url: str = SONARCLOUD_BASE_URL,
) -> dict[str, Any]:
    """Perform an HTTPS GET against the SonarQube Cloud API and return JSON."""
    parsed_base = urllib.parse.urlparse(base_url)
    if parsed_base.scheme != "https" or parsed_base.netloc.lower() != SONARCLOUD_HOST:
        raise ValueError(f"Unsupported SonarQube Cloud base URL: {base_url!r}")

    query = urllib.parse.urlencode(params)
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}?{query}"
    headers = {"Accept": "application/json", "User-Agent": "picket-sonar-sarif/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:300]
        raise SonarApiError(
            f"SonarQube Cloud API HTTP {exc.code} for {path}: {body}",
            status=exc.code,
        ) from exc
    except urllib.error.URLError as exc:
        raise SonarApiError(f"SonarQube Cloud API request failed for {path}: {exc}") from exc


def lookup_analyzed_sha(
    project_key: str,
    kind: str,
    value: str,
    token: str | None = None,
    fetcher: Any = sonar_get_json,
) -> tuple[bool, str | None]:
    """Return (exists, commit_sha) for the branch or pull request on SonarQube Cloud."""
    if kind == "pull_request":
        data = fetcher("/api/project_pull_requests/list", {"project": project_key}, token=token)
        for pr in data.get("pullRequests", []):
            if str(pr.get("key")) == value:
                commit_sha = (pr.get("commit") or {}).get("sha")
                return True, validate_sha(commit_sha) if commit_sha else None
        return False, None

    data = fetcher("/api/project_branches/list", {"project": project_key}, token=token)
    for branch in data.get("branches", []):
        if branch.get("name") == value:
            commit_sha = (branch.get("commit") or {}).get("sha")
            return True, validate_sha(commit_sha) if commit_sha else None
    return False, None


def verify_target_sha(
    target: SyncTarget,
    token: str | None = None,
    max_attempts: int = 4,
    sleep_seconds: float = 5.0,
    fetcher: Any = sonar_get_json,
    sleeper: Any = time.sleep,
) -> tuple[bool, str]:
    """Check whether SonarQube Cloud's analyzed commit matches target.sha."""
    last_reason = "SonarQube Cloud did not report the target branch/PR"
    for attempt in range(max_attempts):
        exists, analyzed_sha = lookup_analyzed_sha(
            target.project_key,
            target.kind,
            target.value,
            token=token,
            fetcher=fetcher,
        )
        if exists and (analyzed_sha is None or analyzed_sha == target.sha):
            return True, "matched"
        if not exists:
            last_reason = f"{target.kind} {target.value!r} not found on SonarQube Cloud"
        else:
            last_reason = (
                f"SonarQube Cloud analyzed {analyzed_sha}, expected {target.sha}"
            )
        if attempt + 1 < max_attempts:
            sleeper(sleep_seconds)
    return False, last_reason


def fetch_open_issues(
    target: SyncTarget,
    token: str | None = None,
    fetcher: Any = sonar_get_json,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Fetch all unresolved issues and associated rule metadata for a target."""
    issues: list[dict[str, Any]] = []
    rules: dict[str, dict[str, Any]] = {}
    scope_param = "pullRequest" if target.kind == "pull_request" else "branch"

    for page in range(1, MAX_PAGES + 1):
        params = {
            "componentKeys": target.project_key,
            scope_param: target.value,
            "resolved": "false",
            "additionalFields": "rules",
            "ps": str(MAX_PAGE_SIZE),
            "p": str(page),
        }
        payload = fetcher("/api/issues/search", params, token=token)
        page_issues = payload.get("issues") or []
        issues.extend(page_issues)
        for rule in payload.get("rules") or []:
            key = rule.get("key")
            if key:
                rules[key] = rule

        total = int(payload.get("total", len(issues)))
        if len(issues) >= total or not page_issues:
            break

    return issues, rules


def extract_relative_path(component: str, project_key: str) -> str | None:
    """Convert a SonarQube Cloud component key to a safe repo-relative POSIX path."""
    if not component or component == project_key:
        return None
    prefix = f"{project_key}:"
    if component.startswith(prefix):
        raw_path = component[len(prefix) :]
    elif ":" in component:
        raw_path = component.split(":", 1)[1]
    else:
        return None

    rel_path = raw_path.replace("\\", "/").lstrip("/")
    if not rel_path or ".." in rel_path.split("/"):
        return None
    return rel_path


def build_region(text_range: dict[str, Any] | None, fallback_line: Any = None) -> dict[str, int]:
    """Convert a Sonar textRange (0-based offsets) into a SARIF region (1-based columns)."""
    if isinstance(text_range, dict) and text_range.get("startLine"):
        start_line = max(1, int(text_range["startLine"]))
        end_line = max(start_line, int(text_range.get("endLine") or start_line))
        region: dict[str, int] = {"startLine": start_line, "endLine": end_line}

        start_offset = text_range.get("startOffset")
        end_offset = text_range.get("endOffset")
        if isinstance(start_offset, int) and start_offset >= 0:
            start_col = start_offset + 1
            if isinstance(end_offset, int) and (
                end_line > start_line or end_offset > start_offset
            ):
                region["startColumn"] = start_col
                region["endColumn"] = end_offset + 1
            elif end_offset is None:
                region["startColumn"] = start_col
        return region

    line = max(1, int(fallback_line)) if fallback_line else 1
    return {"startLine": line}


def issue_sort_key(issue: dict[str, Any], project_key: str) -> tuple[str, int, int, str, str]:
    rel_path = extract_relative_path(issue.get("component", ""), project_key) or ""
    text_range = issue.get("textRange") or {}
    start_line = int(text_range.get("startLine") or issue.get("line") or 0)
    start_offset = int(text_range.get("startOffset") or 0)
    return (
        rel_path,
        start_line,
        start_offset,
        str(issue.get("rule") or ""),
        str(issue.get("key") or ""),
    )


def build_issue_url(target: SyncTarget, issue_key: str) -> str:
    scope_key = "pullRequest" if target.kind == "pull_request" else "branch"
    query = urllib.parse.urlencode(
        {
            "id": target.project_key,
            scope_key: target.value,
            "open": issue_key,
        }
    )
    return f"{SONARCLOUD_BASE_URL}/project/issues?{query}"


def build_rule_url(organization: str, rule_id: str) -> str:
    query = urllib.parse.urlencode({"open": rule_id, "rule_key": rule_id})
    return f"{SONARCLOUD_BASE_URL}/organizations/{urllib.parse.quote(organization, safe='')}/rules?{query}"


def build_rule_tags(
    rule_meta: dict[str, Any],
    rule_issues: list[dict[str, Any]],
) -> list[str]:
    tags: list[str] = ["sonar"]

    def add_tag(candidate: str | None) -> None:
        if not candidate:
            return
        cleaned = candidate.strip().lower()
        if cleaned and cleaned not in tags and len(tags) < MAX_RULE_TAGS:
            tags.append(cleaned)

    for type_tag in sorted(
        {
            tag
            for issue in rule_issues
            if (tag := TYPE_TAGS.get(str(issue.get("type") or "")))
        }
    ):
        add_tag(type_tag)

    for quality in sorted(
        {
            str(impact.get("softwareQuality") or "")
            for issue in rule_issues
            for impact in (issue.get("impacts") or [])
        }
    ):
        add_tag(quality)

    add_tag(rule_meta.get("lang"))
    for tag in sorted(
        {str(t) for issue in rule_issues for t in (issue.get("tags") or [])}
    ):
        add_tag(tag)

    return tags


def build_sarif_rule(
    rule_id: str,
    rule_meta: dict[str, Any],
    rule_issues: list[dict[str, Any]],
    organization: str,
) -> dict[str, Any]:
    name = str(rule_meta.get("name") or rule_id)
    highest_severity = max(
        (str(i.get("severity") or "MAJOR") for i in rule_issues),
        key=lambda sev: SEVERITY_RANK.get(sev, 2),
        default="MAJOR",
    )
    is_vulnerability = any(i.get("type") == "VULNERABILITY" for i in rule_issues)
    types_list = sorted({str(i.get("type") or "UNKNOWN") for i in rule_issues})
    lang_name = str(rule_meta.get("langName") or rule_meta.get("lang") or "Unknown")
    rule_url = build_rule_url(organization, rule_id)

    help_text = (
        f"SonarQube Cloud rule {rule_id} ({lang_name}, {', '.join(types_list)}): "
        f"{name}. Documentation: {rule_url}"
    )
    help_markdown = (
        f"**{name}**\n\n"
        f"- **Rule:** `{rule_id}`\n"
        f"- **Language:** {lang_name}\n"
        f"- **Type:** {', '.join(types_list)}\n"
        f"- **Documentation:** [{rule_id} on SonarQube Cloud]({rule_url})"
    )

    properties: dict[str, Any] = {"tags": build_rule_tags(rule_meta, rule_issues)}
    if is_vulnerability:
        properties["security-severity"] = SECURITY_SEVERITY_BY_SONAR.get(
            highest_severity, "5.5"
        )

    return {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": name},
        "fullDescription": {"text": name},
        "helpUri": rule_url,
        "help": {"text": help_text, "markdown": help_markdown},
        "defaultConfiguration": {
            "level": SARIF_LEVEL_BY_SEVERITY.get(highest_severity, "warning")
        },
        "properties": properties,
    }


def build_related_locations(
    issue: dict[str, Any],
    project_key: str,
) -> list[dict[str, Any]]:
    related: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int, str]] = set()

    for flow in issue.get("flows") or []:
        for loc in flow.get("locations") or []:
            rel_path = extract_relative_path(str(loc.get("component") or ""), project_key)
            if not rel_path:
                continue
            region = build_region(loc.get("textRange"))
            msg = str(loc.get("msg") or "Related location")
            dedupe_key = (rel_path, region["startLine"], region.get("startColumn", 0), msg)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            related.append(
                {
                    "id": len(related) + 1,
                    "message": {"text": msg},
                    "physicalLocation": {
                        "artifactLocation": {"uri": rel_path},
                        "region": region,
                    },
                }
            )
    return related


def build_sarif(
    target: SyncTarget,
    issues: list[dict[str, Any]],
    rules_by_key: dict[str, dict[str, Any]],
    organization: str | None = None,
) -> dict[str, Any]:
    """Convert SonarQube Cloud issues and rules into a SARIF 2.1.0 document."""
    org = organization or next(
        (str(i["organization"]) for i in issues if i.get("organization")),
        target.project_key.split("_", 1)[0],
    )

    sorted_issues = sorted(issues, key=lambda i: issue_sort_key(i, target.project_key))
    issues_by_rule: dict[str, list[dict[str, Any]]] = {}
    results: list[dict[str, Any]] = []

    for issue in sorted_issues:
        rel_path = extract_relative_path(str(issue.get("component") or ""), target.project_key)
        if not rel_path:
            print(
                f"Skipping issue {issue.get('key')} without a file path "
                f"(component={issue.get('component')!r})",
                file=sys.stderr,
            )
            continue

        rule_id = str(issue.get("rule") or "sonar:unknown")
        issues_by_rule.setdefault(rule_id, []).append(issue)

        region = build_region(issue.get("textRange"), issue.get("line"))
        severity = str(issue.get("severity") or "MAJOR")
        message_text = str(issue.get("message") or rule_id)
        issue_key = str(issue.get("key") or "")
        if issue_key:
            full_message = f"{message_text}\n\nSonarQube Cloud issue: {build_issue_url(target, issue_key)}"
        else:
            full_message = message_text

        base_hash = str(issue.get("hash") or "")
        if not base_hash:
            start_col = region.get("startColumn", 0)
            digest_input = (
                f"{rule_id}\0{rel_path}\0{region['startLine']}\0{start_col}\0{message_text}"
            )
            base_hash = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:32]
        # Pair Sonar's line hash with its immutable issue key so identical lines
        # stay distinct and resolving one issue never shifts another's fingerprint.
        if issue_key:
            fingerprint = f"{base_hash}:{issue_key}"
        else:
            start_col = region.get("startColumn", 0)
            fingerprint = f"{base_hash}:{region['startLine']}:{start_col}"

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": SARIF_LEVEL_BY_SEVERITY.get(severity, "warning"),
            "message": {"text": full_message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": rel_path},
                        "region": region,
                    }
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": fingerprint,
            },
        }
        related = build_related_locations(issue, target.project_key)
        if related:
            result["relatedLocations"] = related
        results.append(result)

    sarif_rules = [
        build_sarif_rule(rule_id, rules_by_key.get(rule_id, {}), rule_issues, org)
        for rule_id, rule_issues in sorted(issues_by_rule.items())
    ]

    scope_key = "pullRequest" if target.kind == "pull_request" else "branch"
    info_uri = (
        f"{SONARCLOUD_BASE_URL}/dashboard?"
        f"{urllib.parse.urlencode({'id': target.project_key, scope_key: target.value})}"
    )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": info_uri,
                        "rules": sarif_rules,
                    }
                },
                "results": results,
            }
        ],
    }


def emit_json(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")


def resolve_cli_target(
    args: argparse.Namespace,
    token: str | None,
) -> tuple[SyncTarget | None, str | None]:
    project_key = (
        validate_project_key(args.project_key)
        if args.project_key
        else default_project_key(args.repository or os.environ.get("GITHUB_REPOSITORY"))
    )

    if args.check_run_url is not None:
        if not args.head_sha:
            return None, "Missing check_run head SHA"
        target = parse_check_run_url(
            args.check_run_url,
            args.head_sha,
            expected_project_key=project_key,
        )
        if target is None:
            return None, f"Ignoring check_run URL {args.check_run_url!r}"
        return target, None

    if args.pull_request:
        pr_number = validate_pr_number(args.pull_request)
        if args.head_sha:
            sha = validate_sha(args.head_sha)
        else:
            exists, analyzed_sha = lookup_analyzed_sha(
                project_key, "pull_request", pr_number, token=token
            )
            if not exists or not analyzed_sha:
                return None, f"Pull request #{pr_number} not found on SonarQube Cloud"
            sha = analyzed_sha
        return (
            SyncTarget(
                project_key=project_key,
                kind="pull_request",
                value=pr_number,
                ref=f"refs/pull/{pr_number}/head",
                sha=sha,
            ),
            None,
        )

    branch = validate_branch_name(args.branch)
    if args.head_sha:
        sha = validate_sha(args.head_sha)
    else:
        exists, analyzed_sha = lookup_analyzed_sha(project_key, "branch", branch, token=token)
        if not exists:
            return None, f"Branch {branch!r} not found on SonarQube Cloud"
        if analyzed_sha:
            sha = analyzed_sha
        elif args.fallback_sha:
            sha = validate_sha(args.fallback_sha)
        else:
            return None, f"Branch {branch!r} has no analyzed commit SHA on SonarQube Cloud"
    return (
        SyncTarget(
            project_key=project_key,
            kind="branch",
            value=branch,
            ref=f"refs/heads/{branch}",
            sha=sha,
        ),
        None,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export open SonarQube Cloud issues to SARIF 2.1.0."
    )
    parser.add_argument("--project-key", help="SonarQube Cloud project key")
    parser.add_argument("--repository", help="GitHub owner/repo used to derive project key")
    parser.add_argument("--organization", help="SonarQube Cloud organization key")
    parser.add_argument("--check-run-url", help="SonarQube Cloud check_run details_url")
    parser.add_argument("--branch", default="main", help="SonarQube Cloud branch (default: main)")
    parser.add_argument("--pull-request", help="SonarQube Cloud pull request number")
    parser.add_argument("--head-sha", help="Explicit 40-char commit SHA to attach SARIF to")
    parser.add_argument("--fallback-sha", help="Fallback SHA when SonarQube Cloud omits branch SHA")
    parser.add_argument(
        "--verify-sha",
        action="store_true",
        help="Verify SonarQube Cloud's latest analyzed SHA matches --head-sha before exporting",
    )
    parser.add_argument(
        "--sarif-only",
        action="store_true",
        help="Write only the SARIF 2.1.0 JSON document to stdout instead of the metadata envelope",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    token = os.environ.get("SONAR_TOKEN") or None

    target, skip_reason = resolve_cli_target(args, token)
    if target is None:
        print(f"Skipping SonarQube Cloud SARIF export: {skip_reason}", file=sys.stderr)
        if not args.sarif_only:
            emit_json({"skip": True, "reason": skip_reason})
        return 0

    if args.verify_sha:
        matched, reason = verify_target_sha(target, token=token)
        if not matched:
            print(f"Skipping SonarQube Cloud SARIF export: {reason}", file=sys.stderr)
            if not args.sarif_only:
                emit_json({"skip": True, "reason": reason})
            return 0

    try:
        issues, rules = fetch_open_issues(target, token=token)
    except SonarApiError as exc:
        if exc.status == 404:
            print(f"Skipping SonarQube Cloud SARIF export: {exc}", file=sys.stderr)
            if not args.sarif_only:
                emit_json({"skip": True, "reason": str(exc)})
            return 0
        raise

    sarif = build_sarif(target, issues, rules, organization=args.organization)
    run = sarif["runs"][0]
    results_count = len(run["results"])
    rules_count = len(run["tool"]["driver"]["rules"])
    print(
        f"Exported {results_count} SonarQube Cloud findings across {rules_count} rules "
        f"for {target.ref} @ {target.sha}",
        file=sys.stderr,
    )
    if args.sarif_only:
        emit_json(sarif)
    else:
        emit_json(
            {
                "skip": False,
                "ref": target.ref,
                "sha": target.sha,
                "issues_count": results_count,
                "rules_count": rules_count,
                "sarif": sarif,
            }
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

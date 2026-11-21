#!/usr/bin/env python3
"""Validate Keyring's Microsoft Sentinel ARM templates, Content Hub V3 package,
YAML rules/queries/parsers, and KQL syntax.

Zero third-party Python dependencies required.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

# Allow importing package.py helpers directly.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import package as packager  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
INFRA_SENTINEL = REPO_ROOT / "infra" / "sentinel"
SOLUTION_DIR = REPO_ROOT / "Solutions" / "Keyring"

UUID_V4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
TIMESPAN_RE = re.compile(r"^(\d+)([mhd])$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

VALID_SEVERITIES = {"Informational", "Low", "Medium", "High"}
VALID_STATUSES = {"Available", "InProgress", "Deprecated"}
VALID_KINDS = {"Scheduled", "NRT"}
VALID_OPERATORS = {"gt", "lt", "eq", "ne", "GreaterThan", "LessThan", "Equal", "NotEqual"}
VALID_TACTICS = {
    "Reconnaissance",
    "ResourceDevelopment",
    "InitialAccess",
    "Execution",
    "Persistence",
    "PrivilegeEscalation",
    "DefenseEvasion",
    "CredentialAccess",
    "Discovery",
    "LateralMovement",
    "Collection",
    "CommandAndControl",
    "Exfiltration",
    "Impact",
    "ImpairProcessControl",
    "InhibitResponseFunction",
}
VALID_ENTITY_IDENTIFIERS: dict[str, set[str]] = {
    "Account": {
        "Name",
        "FullName",
        "NTDomain",
        "DnsDomain",
        "UPNSuffix",
        "Sid",
        "AadUserId",
        "Puid",
        "IsDomainJoined",
        "DisplayName",
        "ObjectGuid",
    },
    "IP": {"Address"},
    "AzureResource": {"ResourceId"},
    "Host": {"HostName", "FullName", "DnsDomain", "NTDomain", "AzureID", "OMSAgentID"},
    "URL": {"Url"},
    "CloudApplication": {"AppId", "Name", "InstanceName"},
}

HUNTING_FORBIDDEN_FIELDS = {
    "kind",
    "severity",
    "queryFrequency",
    "queryPeriod",
    "triggerOperator",
    "triggerThreshold",
    "alertDetailsOverride",
    "eventGroupingSettings",
}

KNOWN_TABLES = (
    "KeyringAudit_CL",
    "AZKVAuditLogs",
    "AzureDiagnostics",
    "vimAuditEventKeyring",
)

RULE_SOURCE_MAP = {
    "KeyringManyReveals.yaml": "many-reveals.kql",
    "KeyringRevealNewIp.yaml": "reveal-new-ip.kql",
    "KeyringDeniedProbing.yaml": "denied-probing.kql",
    "KeyringOffHoursSensitiveAction.yaml": "off-hours.kql",
    "KeyringForgedOrCrossSiteRequests.yaml": "app-attack.kql",
    "KeyringSecretShares.yaml": "shares.kql",
    "KeyringAuditGap.yaml": "audit-gap.kql",
    "KeyringUnmatchedSecretGet.yaml": "unmatched-secret-get.kql",
}

HUNTING_SOURCE_MAP = {
    "KeyringSecretValuesRead.yaml": "secret-values-read.kql",
    "KeyringPrivateKeysDownloaded.yaml": "private-keys-downloaded.kql",
    "KeyringDeletesPurgesRecoveries.yaml": "deletes-purges-recoveries.kql",
    "KeyringRefusedAndDenied.yaml": "refused-and-denied.kql",
    "KeyringPersonActivity.yaml": "person-activity.kql",
    "KeyringKeyVaultSideBySide.yaml": "side-by-side.kql",
}

# Reject accidental real Azure subscription/tenant GUIDs inside templates/docs.
SUBSCRIPTION_ID_RE = re.compile(
    r"/subscriptions/(?!00000000-0000-0000-0000-000000000000)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


class Validator:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.seen_ids: dict[str, str] = {}

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def check_uuid(self, value: Any, where: str) -> None:
        if not isinstance(value, str) or not UUID_V4_RE.fullmatch(value):
            self.error(f"{where}: invalid UUID v4 id {value!r}")
            return
        if value in self.seen_ids:
            self.error(f"{where}: duplicate id {value} (already used by {self.seen_ids[value]})")
        else:
            self.seen_ids[value] = where

    def check_kql(self, query: str, where: str, *, require_let_bindings: bool = False) -> None:
        if not isinstance(query, str) or not query.strip():
            self.error(f"{where}: KQL query is empty")
            return

        if not any(tbl in query for tbl in KNOWN_TABLES):
            self.error(f"{where}: KQL query does not reference any expected table/parser")

        # Scan for balanced quotes, parentheses and brackets (ignoring // comments).
        in_quote: str | None = None
        escape = False
        paren_depth = 0
        bracket_depth = 0
        code_lines: list[str] = []

        for lineno, raw_line in enumerate(query.splitlines(), start=1):
            i = 0
            line_code: list[str] = []
            while i < len(raw_line):
                ch = raw_line[i]
                if in_quote:
                    if escape:
                        escape = False
                    elif ch == "\\":
                        escape = True
                    elif ch == in_quote:
                        in_quote = None
                    i += 1
                    continue

                if ch == "/" and i + 1 < len(raw_line) and raw_line[i + 1] == "/":
                    break
                if ch in ('"', "'"):
                    in_quote = ch
                    line_code.append(" ")
                    i += 1
                    continue
                if ch == "(":
                    paren_depth += 1
                elif ch == ")":
                    paren_depth -= 1
                    if paren_depth < 0:
                        self.error(f"{where}:{lineno}: unmatched ')' in KQL")
                        paren_depth = 0
                elif ch == "[":
                    bracket_depth += 1
                elif ch == "]":
                    bracket_depth -= 1
                    if bracket_depth < 0:
                        self.error(f"{where}:{lineno}: unmatched ']' in KQL")
                        bracket_depth = 0
                line_code.append(ch)
                i += 1
            if in_quote is not None:
                self.error(f"{where}:{lineno}: unclosed string literal ({in_quote}) in KQL")
                in_quote = None
            code_lines.append("".join(line_code))

        if paren_depth != 0:
            self.error(f"{where}: unbalanced parentheses in KQL (net depth {paren_depth})")
        if bracket_depth != 0:
            self.error(f"{where}: unbalanced square brackets in KQL (net depth {bracket_depth})")

        joined_code = "\n".join(code_lines).strip()
        if joined_code.endswith("|"):
            self.error(f"{where}: KQL query ends with a trailing pipe '|'")
        if re.search(r"\|\s*\|", joined_code):
            self.error(f"{where}: KQL query contains an empty pipe stage '| |'")

        # Check every `let <var> = ...` statement has a terminating semicolon before the final query.
        statements = [s.strip() for s in joined_code.split(";") if s.strip()]
        if not statements:
            self.error(f"{where}: KQL query has no executable statement")
        else:
            if statements[-1].startswith("let "):
                self.error(f"{where}: KQL query ends with a 'let' statement and no tabular expression")
            for stmt in statements[:-1]:
                if not stmt.startswith("let "):
                    self.error(f"{where}: unexpected semicolon after non-let statement: {stmt[:40]!r}")

        if require_let_bindings:
            for line in query.splitlines():
                if line.startswith("// Set by main.bicep: "):
                    needed = [v.strip() for v in line.split(":", 1)[1].split(",") if v.strip()]
                    for var_name in needed:
                        if not re.search(rf"\blet\s+{re.escape(var_name)}\s*=", query):
                            self.error(
                                f"{where}: standalone rule KQL does not bind required variable {var_name!r}"
                            )

    def check_entity_mappings(self, mappings: Any, query: str, where: str) -> None:
        if not isinstance(mappings, list) or not mappings:
            self.error(f"{where}: entityMappings must be a non-empty list")
            return
        for idx, entity in enumerate(mappings):
            etype = entity.get("entityType")
            if etype not in VALID_ENTITY_IDENTIFIERS:
                self.error(f"{where}: entityMappings[{idx}] has unknown entityType {etype!r}")
                continue
            fields = entity.get("fieldMappings")
            if not isinstance(fields, list) or not fields:
                self.error(f"{where}: entityMappings[{idx}] must have non-empty fieldMappings")
                continue
            for fidx, fm in enumerate(fields):
                ident = fm.get("identifier")
                col = fm.get("columnName")
                if ident not in VALID_ENTITY_IDENTIFIERS[etype]:
                    self.error(
                        f"{where}: entityMappings[{idx}].fieldMappings[{fidx}] invalid identifier {ident!r} for {etype}"
                    )
                if not isinstance(col, str) or not col:
                    self.error(f"{where}: entityMappings[{idx}].fieldMappings[{fidx}] missing columnName")
                elif col not in query:
                    self.error(
                        f"{where}: entityMappings columnName {col!r} does not appear in query"
                    )

    def check_required_connectors(self, connectors: Any, where: str) -> None:
        if not isinstance(connectors, list) or not connectors:
            self.error(f"{where}: requiredDataConnectors must be a non-empty list")
            return
        for idx, conn in enumerate(connectors):
            if not isinstance(conn, dict):
                self.error(f"{where}: requiredDataConnectors[{idx}] must be a mapping")
                continue
            if not conn.get("connectorId"):
                self.error(f"{where}: requiredDataConnectors[{idx}] missing connectorId")
            dtypes = conn.get("dataTypes")
            if not isinstance(dtypes, list) or not dtypes:
                self.error(f"{where}: requiredDataConnectors[{idx}] must have non-empty dataTypes")

    def check_tactics_and_techniques(self, item: dict[str, Any], where: str) -> None:
        tactics = item.get("tactics")
        if not isinstance(tactics, list) or not tactics:
            self.error(f"{where}: tactics must be a non-empty list")
        else:
            for tactic in tactics:
                if tactic not in VALID_TACTICS:
                    self.error(f"{where}: invalid MITRE tactic {tactic!r}")
        techniques = item.get("relevantTechniques", [])
        if not isinstance(techniques, list) or not techniques:
            self.error(f"{where}: relevantTechniques must be a non-empty list")
        else:
            for tech in techniques:
                if not isinstance(tech, str) or not TECHNIQUE_RE.fullmatch(tech):
                    self.error(f"{where}: invalid MITRE technique ID {tech!r}")

    def validate_timespans(self, freq: Any, period: Any, where: str) -> None:
        unit_minutes = {"m": 1, "h": 60, "d": 1440}
        m_freq = TIMESPAN_RE.fullmatch(str(freq)) if freq is not None else None
        m_period = TIMESPAN_RE.fullmatch(str(period)) if period is not None else None
        if not m_freq:
            self.error(f"{where}: invalid queryFrequency {freq!r}")
        if not m_period:
            self.error(f"{where}: invalid queryPeriod {period!r}")
        if m_freq and m_period:
            freq_mins = int(m_freq.group(1)) * unit_minutes[m_freq.group(2)]
            period_mins = int(m_period.group(1)) * unit_minutes[m_period.group(2)]
            if freq_mins > period_mins:
                self.error(
                    f"{where}: queryFrequency ({freq}) exceeds queryPeriod ({period})"
                )

    def validate_arm_template(self, path: Path, *, required_params: set[str]) -> None:
        rel = str(path.relative_to(REPO_ROOT))
        raw = path.read_text(encoding="utf-8")
        if SUBSCRIPTION_ID_RE.search(raw):
            self.error(f"{rel}: contains a non-placeholder subscription ID")
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as exc:
            self.error(f"{rel}: invalid JSON: {exc}")
            return

        if not str(doc.get("$schema", "")).startswith(
            "https://schema.management.azure.com/schemas/"
        ):
            self.error(f"{rel}: missing or invalid ARM $schema")
        if not doc.get("contentVersion"):
            self.error(f"{rel}: missing contentVersion")
        params = doc.get("parameters")
        if not isinstance(params, dict):
            self.error(f"{rel}: parameters must be an object")
        else:
            for req in required_params:
                if req not in params:
                    self.error(f"{rel}: missing required parameter {req!r}")
        resources = doc.get("resources")
        if not isinstance(resources, list) or not resources:
            self.error(f"{rel}: resources must be a non-empty list")
        else:
            for idx, res in enumerate(resources):
                for key in ("type", "apiVersion", "name"):
                    if not res.get(key):
                        self.error(f"{rel}: resources[{idx}] missing {key!r}")

        # Verify every parameters('...') and variables('...') reference exists.
        if isinstance(params, dict):
            variables = doc.get("variables", {}) if isinstance(doc.get("variables"), dict) else {}
            for ref in set(re.findall(r"parameters\('([^']+)'\)", raw)):
                if ref not in params:
                    self.error(f"{rel}: references undefined parameter {ref!r}")
            for ref in set(re.findall(r"variables\('([^']+)'\)", raw)):
                if ref not in variables:
                    self.error(f"{rel}: references undefined variable {ref!r}")

    def validate_create_ui_definition(self, path: Path, main_template_path: Path) -> None:
        rel = str(path.relative_to(REPO_ROOT))
        raw = path.read_text(encoding="utf-8")
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as exc:
            self.error(f"{rel}: invalid JSON: {exc}")
            return
        if "CreateUIDefinition" not in str(doc.get("$schema", "")):
            self.error(f"{rel}: missing CreateUIDefinition $schema")
        if doc.get("handler") != "Microsoft.Azure.CreateUIDef":
            self.error(f"{rel}: handler must be Microsoft.Azure.CreateUIDef")
        params = doc.get("parameters", {})
        outputs = params.get("outputs", {})
        for req_out in ("workspace", "workspace-location"):
            if req_out not in outputs:
                self.error(f"{rel}: outputs missing {req_out!r}")
        if main_template_path.exists():
            tpl_params = json.loads(main_template_path.read_text(encoding="utf-8")).get("parameters", {})
            for out_name in outputs:
                if out_name not in tpl_params:
                    self.error(
                        f"{rel}: output {out_name!r} has no matching parameter in {main_template_path.name}"
                    )

    def validate_bicep_arm_parity(self) -> None:
        arm_path = INFRA_SENTINEL / "azuredeploy.json"
        bicep_path = INFRA_SENTINEL / "main.bicep"
        if not arm_path.exists():
            self.error("infra/sentinel/azuredeploy.json does not exist")
            return
        self.validate_arm_template(arm_path, required_params={"workspaceName", "location"})

        if not shutil.which("az"):
            print("WARN: az CLI not found; skipping Bicep-to-ARM parity check", file=sys.stderr)
            return

        proc = subprocess.run(
            ["az", "bicep", "build", "--file", str(bicep_path), "--stdout"],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            self.error(f"az bicep build failed on {bicep_path}: {proc.stderr.strip()}")
            return

        built = json.loads(proc.stdout)
        committed = json.loads(arm_path.read_text(encoding="utf-8"))
        # Ignore Bicep compiler build-version patch/hash metadata differences.
        built.get("metadata", {}).pop("_generator", None)
        committed.get("metadata", {}).pop("_generator", None)
        if built != committed:
            self.error(
                "infra/sentinel/azuredeploy.json is out of date with infra/sentinel/main.bicep. "
                "Regenerate with: az bicep build --file infra/sentinel/main.bicep --outfile infra/sentinel/azuredeploy.json"
            )

    def validate_solution(self) -> None:
        manifest_path = SOLUTION_DIR / "Data" / "Solution_Keyring.json"
        if not manifest_path.exists():
            self.error("Solutions/Keyring/Data/Solution_Keyring.json is missing")
            return
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        for key in ("Name", "Author", "Description", "Metadata", "BasePath", "Version"):
            if not manifest.get(key):
                self.error(f"Solution_Keyring.json missing {key!r}")

        meta_path = SOLUTION_DIR / manifest["Metadata"]
        if not meta_path.exists():
            self.error(f"SolutionMetadata file not found: {meta_path}")
        else:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            for key in ("publisherId", "offerId", "providers", "categories", "support"):
                if key not in meta:
                    self.error(f"SolutionMetadata.json missing {key!r}")

        # Analytic Rules
        analytic_files = manifest.get("Analytic Rules", [])
        if len(analytic_files) != len(RULE_SOURCE_MAP):
            self.error(
                f"Expected {len(RULE_SOURCE_MAP)} analytic rules in Solution_Keyring.json, found {len(analytic_files)}"
            )
        for rel_file in analytic_files:
            path = SOLUTION_DIR / rel_file
            where = str(path.relative_to(REPO_ROOT))
            if not path.exists():
                self.error(f"Manifest lists missing file: {where}")
                continue
            rule = packager.load_yaml(path)
            self.check_uuid(rule.get("id"), where)
            if not rule.get("name"):
                self.error(f"{where}: missing name")
            if not rule.get("description"):
                self.error(f"{where}: missing description")
            if rule.get("severity") not in VALID_SEVERITIES:
                self.error(f"{where}: invalid severity {rule.get('severity')!r}")
            if rule.get("status") not in VALID_STATUSES:
                self.error(f"{where}: invalid status {rule.get('status')!r}")
            if rule.get("kind") not in VALID_KINDS:
                self.error(f"{where}: invalid kind {rule.get('kind')!r}")
            if not SEMVER_RE.fullmatch(str(rule.get("version", ""))):
                self.error(f"{where}: invalid semver version {rule.get('version')!r}")
            if str(rule.get("triggerOperator")) not in VALID_OPERATORS:
                self.error(f"{where}: invalid triggerOperator {rule.get('triggerOperator')!r}")
            if not isinstance(rule.get("triggerThreshold"), int):
                self.error(f"{where}: triggerThreshold must be an integer")
            self.check_required_connectors(rule.get("requiredDataConnectors"), where)
            self.validate_timespans(rule.get("queryFrequency"), rule.get("queryPeriod"), where)
            self.check_tactics_and_techniques(rule, where)
            query = str(rule.get("query", ""))
            self.check_kql(query, where, require_let_bindings=True)
            self.check_entity_mappings(rule.get("entityMappings"), query, where)

            # Verify exact body parity with infra/sentinel/rules/*.kql
            src_kql_name = RULE_SOURCE_MAP.get(path.name)
            if src_kql_name:
                src_kql = (INFRA_SENTINEL / "rules" / src_kql_name).read_text(encoding="utf-8").strip()
                if src_kql not in query:
                    self.error(
                        f"{where}: query drifted from infra/sentinel/rules/{src_kql_name}"
                    )

        # Hunting Queries
        hunting_files = manifest.get("Hunting Queries", [])
        if len(hunting_files) != len(HUNTING_SOURCE_MAP):
            self.error(
                f"Expected {len(HUNTING_SOURCE_MAP)} hunting queries in Solution_Keyring.json, found {len(hunting_files)}"
            )
        for rel_file in hunting_files:
            path = SOLUTION_DIR / rel_file
            where = str(path.relative_to(REPO_ROOT))
            if not path.exists():
                self.error(f"Manifest lists missing file: {where}")
                continue
            hq = packager.load_yaml(path)
            self.check_uuid(hq.get("id"), where)
            for forbidden in HUNTING_FORBIDDEN_FIELDS:
                if forbidden in hq:
                    self.error(f"{where}: hunting query must not define analytic field {forbidden!r}")
            if not hq.get("name") or not hq.get("description"):
                self.error(f"{where}: missing name or description")
            if not SEMVER_RE.fullmatch(str(hq.get("version", ""))):
                self.error(f"{where}: invalid semver version {hq.get('version')!r}")
            self.check_required_connectors(hq.get("requiredDataConnectors"), where)
            self.check_tactics_and_techniques(hq, where)
            query = str(hq.get("query", ""))
            self.check_kql(query, where)
            self.check_entity_mappings(hq.get("entityMappings"), query, where)

            src_kql_name = HUNTING_SOURCE_MAP.get(path.name)
            if src_kql_name:
                src_kql = (INFRA_SENTINEL / "hunting" / src_kql_name).read_text(encoding="utf-8").strip()
                if query.strip() != src_kql:
                    self.error(
                        f"{where}: query drifted from infra/sentinel/hunting/{src_kql_name}"
                    )

        # Parsers
        for rel_file in manifest.get("Parsers", []):
            path = SOLUTION_DIR / rel_file
            where = str(path.relative_to(REPO_ROOT))
            if not path.exists():
                self.error(f"Manifest lists missing file: {where}")
                continue
            parser_doc = packager.load_yaml(path)
            self.check_uuid(parser_doc.get("id"), where)
            pname = parser_doc.get("ParserName", "")
            if not re.fullmatch(r"[A-Za-z0-9_]+", str(pname)):
                self.error(f"{where}: invalid ParserName {pname!r}")
            if pname != path.stem:
                self.error(f"{where}: ParserName {pname!r} does not match filename stem {path.stem!r}")
            query = str(parser_doc.get("ParserQuery", ""))
            self.check_kql(query, where)
            src_parser = INFRA_SENTINEL / "parsers" / f"{pname}.kql"
            if not src_parser.exists():
                self.error(f"{where}: missing source parser {src_parser.relative_to(REPO_ROOT)}")
            elif query.strip() != src_parser.read_text(encoding="utf-8").strip():
                self.error(f"{where}: ParserQuery drifted from {src_parser.relative_to(REPO_ROOT)}")

        # Workbook parity
        for rel_file in manifest.get("Workbooks", []):
            path = SOLUTION_DIR / rel_file
            where = str(path.relative_to(REPO_ROOT))
            if not path.exists():
                self.error(f"Manifest lists missing file: {where}")
                continue
            wb = json.loads(path.read_text(encoding="utf-8"))
            src_wb = json.loads((INFRA_SENTINEL / "workbook.json").read_text(encoding="utf-8"))
            if wb != src_wb:
                self.error(f"{where}: workbook drifted from infra/sentinel/workbook.json")
            for idx, item in enumerate(wb.get("items", [])):
                q = item.get("content", {}).get("query")
                if q:
                    # Workbook queries may contain {TimeRange:start} placeholders.
                    sanitised = re.sub(r"\{[^}]+\}", "now()", q)
                    self.check_kql(sanitised, f"{where} item[{idx}]")

        # Package/mainTemplate.json and Package/createUiDefinition.json
        main_tpl = SOLUTION_DIR / "Package" / "mainTemplate.json"
        ui_def = SOLUTION_DIR / "Package" / "createUiDefinition.json"
        self.validate_arm_template(main_tpl, required_params={"workspace", "workspace-location"})
        self.validate_create_ui_definition(ui_def, main_tpl)

        # Verify Package/mainTemplate.json matches generator output exactly.
        expected = json.dumps(packager.build_main_template(), indent=2) + "\n"
        if main_tpl.exists() and main_tpl.read_text(encoding="utf-8") != expected:
            self.error(
                "Solutions/Keyring/Package/mainTemplate.json is out of date. "
                "Run: python3 tools/sentinel/package.py"
            )

        # Also validate raw KQL files under infra/sentinel/
        for kql_path in sorted(INFRA_SENTINEL.rglob("*.kql")):
            self.check_kql(
                kql_path.read_text(encoding="utf-8"),
                str(kql_path.relative_to(REPO_ROOT)),
            )


def main() -> int:
    validator = Validator()
    validator.validate_bicep_arm_parity()
    validator.validate_solution()
    if validator.errors:
        for err in validator.errors:
            print(f"ERROR: {err}", file=sys.stderr)
        print(f"\nValidation failed with {len(validator.errors)} error(s).", file=sys.stderr)
        return 1
    print("OK: All Microsoft Sentinel ARM templates, Content Hub V3 files, YAML schemas and KQL queries passed validation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

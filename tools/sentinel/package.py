#!/usr/bin/env python3
"""Package Solutions/Keyring into the Microsoft Sentinel Content Hub V3 mainTemplate.json.

Reads Solutions/Keyring/Data/Solution_Keyring.json, SolutionMetadata.json,
Parsers/*.yaml, Analytic Rules/*.yaml, Hunting Queries/*.yaml and
Workbooks/KeyringAudit.json and deterministically generates
Solutions/Keyring/Package/mainTemplate.json.

No third-party Python packages are required: YAML is loaded via PyYAML if
installed, falling back to `yq -o=json` or Ruby's standard library YAML module.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SOLUTION_DIR = REPO_ROOT / "Solutions" / "Keyring"
DATA_MANIFEST = SOLUTION_DIR / "Data" / "Solution_Keyring.json"
MAIN_TEMPLATE_PATH = SOLUTION_DIR / "Package" / "mainTemplate.json"

WORKBOOK_CONTENT_ID = "6c5d1f4b-9e70-4b25-94f8-0a1b2c3d4e01"

OPERATOR_MAP = {
    "gt": "GreaterThan",
    "lt": "LessThan",
    "eq": "Equal",
    "ne": "NotEqual",
    "GreaterThan": "GreaterThan",
    "LessThan": "LessThan",
    "Equal": "Equal",
    "NotEqual": "NotEqual",
}


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore[import-not-found]

        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            raise ValueError(f"{path}: expected YAML mapping")
        return data
    except ModuleNotFoundError:
        pass

    if shutil.which("yq"):
        proc = subprocess.run(
            ["yq", "-o=json", ".", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(proc.stdout)
        if not isinstance(data, dict):
            raise ValueError(f"{path}: expected YAML mapping")
        return data

    if shutil.which("ruby"):
        proc = subprocess.run(
            [
                "ruby",
                "-ryaml",
                "-rjson",
                "-e",
                "puts JSON.generate(YAML.safe_load(File.read(ARGV[0])))",
                str(path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(proc.stdout)
        if not isinstance(data, dict):
            raise ValueError(f"{path}: expected YAML mapping")
        return data

    raise RuntimeError(
        "Unable to parse YAML: install PyYAML, yq, or ruby."
    )


def escape_arm_literal(value: str) -> str:
    if value.startswith("["):
        return "[" + value
    return value


def kql_timespan_to_iso8601(span: str) -> str:
    match = re.fullmatch(r"(\d+)([mhd])", span.strip())
    if not match:
        raise ValueError(f"Unsupported KQL timespan: {span!r}")
    amount = int(match.group(1))
    unit = match.group(2)
    if unit == "m":
        return f"PT{amount}M"
    if unit == "h":
        return f"PT{amount}H"
    return f"P{amount}D"


def format_parser_params(params: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for param in params:
        name = param["Name"]
        ptype = param["Type"]
        default = param["Default"]
        if isinstance(default, bool):
            default_str = "True" if default else "False"
        elif ptype == "string":
            escaped = str(default).replace("'", "\\'")
            default_str = f"'{escaped}'"
        else:
            default_str = str(default)
        parts.append(f"{name}:{ptype}={default_str}")
    return ", ".join(parts)


def make_metadata_resource(
    *,
    name_expr: str,
    parent_id_expr: str,
    content_id: str,
    kind: str,
    version: str,
    categories: dict[str, Any],
    providers: list[str],
    first_publish_date: str,
    last_publish_date: str,
) -> dict[str, Any]:
    return {
        "type": "Microsoft.OperationalInsights/workspaces/providers/metadata",
        "apiVersion": "2022-01-01-preview",
        "name": name_expr,
        "properties": {
            "parentId": parent_id_expr,
            "contentId": content_id,
            "kind": kind,
            "version": version,
            "source": {
                "kind": "Solution",
                "name": "[variables('_solutionName')]",
                "sourceId": "[variables('_solutionId')]",
            },
            "author": {
                "name": "[variables('_solutionAuthor')]",
            },
            "support": {
                "name": "[variables('_solutionAuthor')]",
                "tier": "[variables('_solutionTier')]",
                "link": "[variables('_solutionSupportLink')]",
            },
            "categories": categories,
            "providers": providers,
            "firstPublishDate": first_publish_date,
            "lastPublishDate": last_publish_date,
            "contentSchemaVersion": "3.0.0",
        },
    }


def build_main_template() -> dict[str, Any]:
    manifest = json.loads(DATA_MANIFEST.read_text(encoding="utf-8"))
    metadata = json.loads((SOLUTION_DIR / manifest["Metadata"]).read_text(encoding="utf-8"))

    solution_name = manifest["Name"]
    solution_version = manifest["Version"]
    publisher_id = metadata["publisherId"]
    offer_id = metadata["offerId"]
    solution_id = f"{publisher_id}.{offer_id}"
    providers = metadata["providers"]
    categories = metadata["categories"]
    support = metadata["support"]
    first_publish = metadata["firstPublishDate"]
    last_publish = metadata["lastPublishDate"]

    package_depends_on = (
        "[extensionResourceId("
        "resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace')), "
        "'Microsoft.SecurityInsights/contentPackages', variables('_solutionId'))]"
    )

    resources: list[dict[str, Any]] = []
    dependencies_criteria: list[dict[str, str]] = []

    # 1. Parsers (contentTemplates + workspace savedSearches so functions are immediately usable)
    parsers: list[dict[str, Any]] = []
    for rel_path in manifest.get("Parsers", []):
        parsers.append(load_yaml(SOLUTION_DIR / rel_path))

    for parser in parsers:
        content_id = parser["id"]
        fn_name = parser["ParserName"]
        version = str(parser["Parser"]["Version"])
        title = parser["Parser"]["Title"]
        query = escape_arm_literal(parser["ParserQuery"].rstrip("\n"))
        schema = parser["Normalization"]["Schema"]
        schema_version = str(parser["Normalization"]["Version"])

        saved_search_props: dict[str, Any] = {
            "category": "ASIM",
            "displayName": title,
            "query": query,
            "functionAlias": fn_name,
            "version": 2,
            "tags": [
                {"name": "Schema", "value": schema},
                {"name": "SchemaVersion", "value": schema_version},
            ],
        }
        if parser.get("ParserParams"):
            saved_search_props["functionParameters"] = format_parser_params(
                parser["ParserParams"]
            )

        direct_search: dict[str, Any] = {
            "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
            "apiVersion": "2020-08-01",
            "name": f"[concat(parameters('workspace'), '/{fn_name}')]",
            "properties": saved_search_props,
        }
        if fn_name == "ASimAuditEventKeyring":
            direct_search["dependsOn"] = [
                "[resourceId('Microsoft.OperationalInsights/workspaces/savedSearches', parameters('workspace'), 'vimAuditEventKeyring')]"
            ]
        resources.append(direct_search)

        nested_search = {
            "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
            "apiVersion": "2020-08-01",
            "name": f"[concat(parameters('workspace'), '/{fn_name}')]",
            "properties": saved_search_props,
        }
        nested_meta = make_metadata_resource(
            name_expr=f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/parser-{content_id}')]",
            parent_id_expr=f"[resourceId('Microsoft.OperationalInsights/workspaces/savedSearches', parameters('workspace'), '{fn_name}')]",
            content_id=content_id,
            kind="Parser",
            version=version,
            categories=categories,
            providers=providers,
            first_publish_date=first_publish,
            last_publish_date=last_publish,
        )

        resources.append(
            {
                "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
                "apiVersion": "2023-04-01-preview",
                "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/{content_id}-parser-{version}')]",
                "location": "[parameters('workspace-location')]",
                "dependsOn": [package_depends_on],
                "properties": {
                    "contentId": content_id,
                    "displayName": title,
                    "contentKind": "Parser",
                    "contentSchemaVersion": "3.0.0",
                    "packageId": "[variables('_solutionId')]",
                    "packageKind": "Solution",
                    "packageName": "[variables('_solutionName')]",
                    "packageVersion": "[variables('_solutionVersion')]",
                    "version": version,
                    "source": {
                        "kind": "Solution",
                        "name": "[variables('_solutionName')]",
                        "sourceId": "[variables('_solutionId')]",
                    },
                    "author": {"name": "[variables('_solutionAuthor')]"},
                    "support": {
                        "name": "[variables('_solutionAuthor')]",
                        "tier": "[variables('_solutionTier')]",
                        "link": "[variables('_solutionSupportLink')]",
                    },
                    "categories": categories,
                    "mainTemplate": {
                        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                        "contentVersion": "1.0.0.0",
                        "parameters": {},
                        "variables": {},
                        "resources": [nested_search, nested_meta],
                    },
                },
            }
        )
        dependencies_criteria.append(
            {"kind": "Parser", "contentId": content_id, "version": version}
        )

    # 2. Analytic Rules (contentTemplates wrapping alertRuleTemplates; never auto-enabled)
    for rel_path in manifest.get("Analytic Rules", []):
        rule = load_yaml(SOLUTION_DIR / rel_path)
        content_id = rule["id"]
        version = str(rule["version"])
        display_name = rule["name"]
        description = rule["description"].strip()
        query = escape_arm_literal(rule["query"].rstrip("\n"))

        rule_template_props: dict[str, Any] = {
            "description": description,
            "displayName": display_name,
            "query": query,
            "queryFrequency": kql_timespan_to_iso8601(str(rule["queryFrequency"])),
            "queryPeriod": kql_timespan_to_iso8601(str(rule["queryPeriod"])),
            "severity": rule["severity"],
            "status": rule.get("status", "Available"),
            "tactics": rule["tactics"],
            "techniques": rule.get("relevantTechniques", []),
            "triggerOperator": OPERATOR_MAP[str(rule["triggerOperator"])],
            "triggerThreshold": int(rule["triggerThreshold"]),
            "version": version,
            "entityMappings": rule["entityMappings"],
            "requiredDataConnectors": rule["requiredDataConnectors"],
            "eventGroupingSettings": rule.get(
                "eventGroupingSettings", {"aggregationKind": "AlertPerResult"}
            ),
        }

        nested_rule = {
            "type": "Microsoft.OperationalInsights/workspaces/providers/alertRuleTemplates",
            "apiVersion": "2023-02-01-preview",
            "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/{content_id}')]",
            "kind": rule.get("kind", "Scheduled"),
            "properties": rule_template_props,
        }
        nested_meta = make_metadata_resource(
            name_expr=f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/analyticsrule-{content_id}')]",
            parent_id_expr=f"[extensionResourceId(resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace')), 'Microsoft.SecurityInsights/alertRuleTemplates', '{content_id}')]",
            content_id=content_id,
            kind="AnalyticsRule",
            version=version,
            categories=categories,
            providers=providers,
            first_publish_date=first_publish,
            last_publish_date=last_publish,
        )

        resources.append(
            {
                "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
                "apiVersion": "2023-04-01-preview",
                "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/{content_id}-analyticsrule-{version}')]",
                "location": "[parameters('workspace-location')]",
                "dependsOn": [package_depends_on],
                "properties": {
                    "contentId": content_id,
                    "displayName": display_name,
                    "contentKind": "AnalyticsRule",
                    "contentSchemaVersion": "3.0.0",
                    "packageId": "[variables('_solutionId')]",
                    "packageKind": "Solution",
                    "packageName": "[variables('_solutionName')]",
                    "packageVersion": "[variables('_solutionVersion')]",
                    "version": version,
                    "source": {
                        "kind": "Solution",
                        "name": "[variables('_solutionName')]",
                        "sourceId": "[variables('_solutionId')]",
                    },
                    "author": {"name": "[variables('_solutionAuthor')]"},
                    "support": {
                        "name": "[variables('_solutionAuthor')]",
                        "tier": "[variables('_solutionTier')]",
                        "link": "[variables('_solutionSupportLink')]",
                    },
                    "categories": categories,
                    "mainTemplate": {
                        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                        "contentVersion": "1.0.0.0",
                        "parameters": {},
                        "variables": {},
                        "resources": [nested_rule, nested_meta],
                    },
                },
            }
        )
        dependencies_criteria.append(
            {"kind": "AnalyticsRule", "contentId": content_id, "version": version}
        )

    # 3. Hunting Queries (contentTemplates wrapping savedSearches in Hunting Queries category)
    for rel_path in manifest.get("Hunting Queries", []):
        hq = load_yaml(SOLUTION_DIR / rel_path)
        content_id = hq["id"]
        version = str(hq["version"])
        display_name = hq["name"]
        description = hq["description"].strip()
        query = escape_arm_literal(hq["query"].rstrip("\n"))

        tags = [
            {"name": "description", "value": description},
            {"name": "tactics", "value": ",".join(hq["tactics"])},
        ]
        if hq.get("relevantTechniques"):
            tags.append(
                {"name": "techniques", "value": ",".join(hq["relevantTechniques"])}
            )

        nested_hq = {
            "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
            "apiVersion": "2020-08-01",
            "name": f"[concat(parameters('workspace'), '/{content_id}')]",
            "properties": {
                "category": "Hunting Queries",
                "displayName": display_name,
                "query": query,
                "version": 2,
                "tags": tags,
            },
        }
        nested_meta = make_metadata_resource(
            name_expr=f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/huntingquery-{content_id}')]",
            parent_id_expr=f"[resourceId('Microsoft.OperationalInsights/workspaces/savedSearches', parameters('workspace'), '{content_id}')]",
            content_id=content_id,
            kind="HuntingQuery",
            version=version,
            categories=categories,
            providers=providers,
            first_publish_date=first_publish,
            last_publish_date=last_publish,
        )

        resources.append(
            {
                "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
                "apiVersion": "2023-04-01-preview",
                "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/{content_id}-huntingquery-{version}')]",
                "location": "[parameters('workspace-location')]",
                "dependsOn": [package_depends_on],
                "properties": {
                    "contentId": content_id,
                    "displayName": display_name,
                    "contentKind": "HuntingQuery",
                    "contentSchemaVersion": "3.0.0",
                    "packageId": "[variables('_solutionId')]",
                    "packageKind": "Solution",
                    "packageName": "[variables('_solutionName')]",
                    "packageVersion": "[variables('_solutionVersion')]",
                    "version": version,
                    "source": {
                        "kind": "Solution",
                        "name": "[variables('_solutionName')]",
                        "sourceId": "[variables('_solutionId')]",
                    },
                    "author": {"name": "[variables('_solutionAuthor')]"},
                    "support": {
                        "name": "[variables('_solutionAuthor')]",
                        "tier": "[variables('_solutionTier')]",
                        "link": "[variables('_solutionSupportLink')]",
                    },
                    "categories": categories,
                    "mainTemplate": {
                        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                        "contentVersion": "1.0.0.0",
                        "parameters": {},
                        "variables": {},
                        "resources": [nested_hq, nested_meta],
                    },
                },
            }
        )
        dependencies_criteria.append(
            {"kind": "HuntingQuery", "contentId": content_id, "version": version}
        )

    # 4. Workbook (contentTemplate + direct workbook resource)
    for rel_path in manifest.get("Workbooks", []):
        wb_raw = (SOLUTION_DIR / rel_path).read_text(encoding="utf-8")
        # Compact canonical JSON string for serializedData.
        wb_serialized = json.dumps(json.loads(wb_raw), separators=(",", ":"))
        wb_version = "1.0.0"

        workbook_resource = {
            "type": "Microsoft.Insights/workbooks",
            "apiVersion": "2023-06-01",
            "name": "[parameters('workbook1-id')]",
            "location": "[parameters('workspace-location')]",
            "kind": "shared",
            "properties": {
                "displayName": "[parameters('workbook1-name')]",
                "serializedData": wb_serialized,
                "version": "1.0",
                "sourceId": "[variables('workspaceResourceId')]",
                "category": "sentinel",
            },
        }
        resources.append(workbook_resource)

        nested_meta = make_metadata_resource(
            name_expr=f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/workbook-{WORKBOOK_CONTENT_ID}')]",
            parent_id_expr="[resourceId('Microsoft.Insights/workbooks', parameters('workbook1-id'))]",
            content_id=WORKBOOK_CONTENT_ID,
            kind="Workbook",
            version=wb_version,
            categories=categories,
            providers=providers,
            first_publish_date=first_publish,
            last_publish_date=last_publish,
        )

        resources.append(
            {
                "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
                "apiVersion": "2023-04-01-preview",
                "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/{WORKBOOK_CONTENT_ID}-workbook-{wb_version}')]",
                "location": "[parameters('workspace-location')]",
                "dependsOn": [package_depends_on],
                "properties": {
                    "contentId": WORKBOOK_CONTENT_ID,
                    "displayName": "[parameters('workbook1-name')]",
                    "contentKind": "Workbook",
                    "contentSchemaVersion": "3.0.0",
                    "packageId": "[variables('_solutionId')]",
                    "packageKind": "Solution",
                    "packageName": "[variables('_solutionName')]",
                    "packageVersion": "[variables('_solutionVersion')]",
                    "version": wb_version,
                    "source": {
                        "kind": "Solution",
                        "name": "[variables('_solutionName')]",
                        "sourceId": "[variables('_solutionId')]",
                    },
                    "author": {"name": "[variables('_solutionAuthor')]"},
                    "support": {
                        "name": "[variables('_solutionAuthor')]",
                        "tier": "[variables('_solutionTier')]",
                        "link": "[variables('_solutionSupportLink')]",
                    },
                    "categories": categories,
                    "mainTemplate": {
                        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                        "contentVersion": "1.0.0.0",
                        "parameters": {},
                        "variables": {},
                        "resources": [workbook_resource, nested_meta],
                    },
                },
            }
        )
        dependencies_criteria.append(
            {
                "kind": "Workbook",
                "contentId": WORKBOOK_CONTENT_ID,
                "version": wb_version,
            }
        )

    # 5. Content Hub V3 Solution contentPackages resource (inserted first)
    content_package = {
        "type": "Microsoft.OperationalInsights/workspaces/providers/contentPackages",
        "apiVersion": "2023-04-01-preview",
        "name": "[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', variables('_solutionId'))]",
        "location": "[parameters('workspace-location')]",
        "properties": {
            "version": "[variables('_solutionVersion')]",
            "kind": "Solution",
            "contentSchemaVersion": "3.0.0",
            "displayName": "[variables('_solutionName')]",
            "publisherDisplayName": "[variables('_solutionAuthor')]",
            "descriptionHtml": manifest["Description"],
            "contentId": "[variables('_solutionId')]",
            "contentKind": "Solution",
            "contentProductId": "[variables('_solutionProductId')]",
            "id": "[variables('_solutionId')]",
            "icon": manifest["Logo"],
            "categories": categories,
            "dependencies": {
                "operator": "AND",
                "criteria": dependencies_criteria,
            },
            "firstPublishDate": first_publish,
            "lastPublishDate": last_publish,
            "providers": providers,
            "source": {
                "kind": "Solution",
                "name": "[variables('_solutionName')]",
                "sourceId": "[variables('_solutionId')]",
            },
            "author": {"name": "[variables('_solutionAuthor')]"},
            "support": {
                "name": support["name"],
                "tier": support["tier"],
                "link": support["link"],
            },
        },
    }
    resources.insert(0, content_package)

    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "author": solution_name,
            "comments": "Microsoft Sentinel Content Hub V3 solution package for Keyring. Generated by tools/sentinel/package.py.",
        },
        "parameters": {
            "workspace-location": {
                "type": "string",
                "defaultValue": "[resourceGroup().location]",
                "metadata": {
                    "description": "Region of the Log Analytics workspace."
                },
            },
            "workspace": {
                "type": "string",
                "metadata": {
                    "description": "Name of the Log Analytics workspace that holds KeyringAudit_CL, with Microsoft Sentinel enabled."
                },
            },
            "workbook1-name": {
                "type": "string",
                "defaultValue": "Keyring audit",
                "metadata": {
                    "description": "Display name for the Keyring audit workbook."
                },
            },
            "workbook1-id": {
                "type": "string",
                "defaultValue": "[newGuid()]",
                "metadata": {
                    "description": "Unique identifier for the Keyring audit workbook resource."
                },
            },
        },
        "variables": {
            "_solutionName": solution_name,
            "_solutionVersion": solution_version,
            "_solutionId": solution_id,
            "_solutionProductId": solution_id,
            "_solutionAuthor": support["name"],
            "_solutionTier": support["tier"],
            "_solutionSupportLink": support["link"],
            "workspaceResourceId": "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace'))]",
        },
        "resources": resources,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail instead of writing if Package/mainTemplate.json differs from generated output.",
    )
    args = parser.parse_args()

    template = build_main_template()
    rendered = json.dumps(template, indent=2) + "\n"

    if args.check:
        if not MAIN_TEMPLATE_PATH.exists():
            print(f"ERROR: {MAIN_TEMPLATE_PATH} does not exist.", file=sys.stderr)
            return 1
        existing = MAIN_TEMPLATE_PATH.read_text(encoding="utf-8")
        if existing != rendered:
            print(
                f"ERROR: {MAIN_TEMPLATE_PATH} is out of date. Run: python3 tools/sentinel/package.py",
                file=sys.stderr,
            )
            return 1
        print(f"OK: {MAIN_TEMPLATE_PATH.relative_to(REPO_ROOT)} is up to date.")
        return 0

    MAIN_TEMPLATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    MAIN_TEMPLATE_PATH.write_text(rendered, encoding="utf-8")
    print(f"Wrote {MAIN_TEMPLATE_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
Enriches a converted SPL query with MITRE ATT&CK context parsed from the
source Sigma rule's metadata (title, level, tags).

The structuring/enrichment pipe template is injected at runtime via the
SPL_ENRICHMENT_PIPES environment variable, which is stored as a GitHub
Actions Secret — keeping it private from anyone reading the workflow file.

Usage:
    python3 scripts/enrich_spl.py <sigma_rule.yml> <base_spl_query_string>

Output:
    Writes an enriched SPL .txt file to spl_output/<rule_stem>.txt
"""

import os
import sys
import yaml
from pathlib import Path

# Maps ATT&CK tactic slugs (from Sigma tags) to human-readable names
TACTIC_MAP = {
    "initial-access":       "Initial Access",
    "execution":            "Execution",
    "persistence":          "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion":      "Defense Evasion",
    "credential-access":    "Credential Access",
    "discovery":            "Discovery",
    "lateral-movement":     "Lateral Movement",
    "collection":           "Collection",
    "command-and-control":  "Command and Control",
    "exfiltration":         "Exfiltration",
    "impact":               "Impact",
    "reconnaissance":       "Reconnaissance",
    "resource-development": "Resource Development",
}


def parse_sigma_tags(tags: list[str]) -> tuple[list[str], list[str]]:
    """
    Splits Sigma ATT&CK tags into human-readable tactics and technique IDs.

    Examples:
        attack.defense-evasion  ->  tactics: ["Defense Evasion"]
        attack.t1059.001        ->  techniques: ["T1059.001"]
    """
    tactics = []
    techniques = []
    for tag in tags:
        tag = tag.strip().lower()
        if not tag.startswith("attack."):
            continue
        suffix = tag.replace("attack.", "", 1)
        if suffix.startswith("t") and suffix[1:2].isdigit():
            # Technique ID (e.g. t1059.001 -> T1059.001)
            techniques.append(suffix.upper())
        else:
            # Tactic slug (e.g. defense-evasion -> "Defense Evasion")
            friendly = TACTIC_MAP.get(suffix, suffix.replace("-", " ").title())
            if friendly not in tactics:
                tactics.append(friendly)
    return tactics, techniques


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: enrich_spl.py <sigma_rule.yml> <base_spl_query>")
        sys.exit(1)

    rule_path = Path(sys.argv[1])
    base_spl  = sys.argv[2].strip()

    # ── Parse Sigma rule metadata ─────────────────────────────────────────────
    with open(rule_path, "r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)

    title     = rule.get("title", "Unknown Detection")
    level     = rule.get("level", "unknown").capitalize()
    tags      = rule.get("tags", [])

    tactics, techniques = parse_sigma_tags(tags)
    tactic_str    = ", ".join(tactics)    if tactics    else "Unknown"
    technique_str = ", ".join(techniques) if techniques else "Unknown"

    # ── Build enriched SPL ────────────────────────────────────────────────────
    # The enrichment pipe template is injected from a GitHub Secret so it stays
    # hidden from anyone reading the public sigma_val.yml workflow file.
    enrichment_template = os.environ.get("SPL_ENRICHMENT_PIPES", "").strip()

    if not enrichment_template:
        print(f"[WARN] SPL_ENRICHMENT_PIPES secret is not set. Saving base SPL only for: {rule_path.name}")
        enriched_spl = base_spl
    else:
        filled_pipes = (
            enrichment_template
            .replace("{title}",     title)
            .replace("{level}",     level)
            .replace("{tactic}",    tactic_str)
            .replace("{technique}", technique_str)
        )
        enriched_spl = base_spl + "\n" + filled_pipes

    # ── Write output ───────────────────────────────────────────────────────────
    output_dir = Path("spl_output")
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / f"{rule_path.stem}.txt"
    output_file.write_text(enriched_spl, encoding="utf-8")

    print(f"\n{'='*60}")
    print(f"Rule       : {title}")
    print(f"Severity   : {level}")
    print(f"Tactics    : {tactic_str}")
    print(f"Techniques : {technique_str}")
    print(f"Output     : {output_file}")
    print(f"{'='*60}\n")
    print("=== Enriched SPL Query ===")
    print(enriched_spl)


if __name__ == "__main__":
    main()

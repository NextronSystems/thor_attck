#!/usr/bin/env python3
"""Build versioned Navigator layers from a THOR signature metadata export."""

import argparse
import csv
import json
from pathlib import Path

if __package__:
    from .audit_attack import Catalog, DOMAINS, active, audit, fingerprint, read_json
else:
    from audit_attack import Catalog, DOMAINS, active, audit, fingerprint, read_json


KINDS = {"yara": "YARA Rule", "sigma": "Sigma Rule"}
LAYER_FILES = {
    "combined": "THOR_APT_Scanner.json",
    "yara": "layers/THOR_APT_Scanner_yara.json",
    "sigma": "layers/THOR_APT_Scanner_sigma.json",
}


def build_layers(rows, catalog, signature_version, source_sha256):
    """Select built-in YARA/Sigma rows and normalize legacy tags at read time."""
    results = {slug: audit(rows, catalog, kind=kind) for slug, kind in KINDS.items()}
    counts = {
        slug: result["selected_direct_counts"] for slug, result in results.items()
    }
    layers, statistics = {}, {}
    for slug, selected_kinds in (
        ("yara", ["yara"]),
        ("sigma", ["sigma"]),
        ("combined", ["yara", "sigma"]),
    ):
        direct = set().union(*(set(counts[k]) for k in selected_kinds))
        parents = {catalog.parents[t] for t in direct if t in catalog.parents}
        annotations = []
        for tid in sorted(direct | parents):
            annotation = {"techniqueID": tid, "enabled": True}
            if tid in direct:
                annotation.update(
                    score=1,
                    comment="Explicit signature-tag association. Detection effectiveness and tactical context have not been validated.",
                    metadata=[
                        {
                            "name": KINDS[k] + " export entries",
                            "value": str(counts[k].get(tid, 0)),
                        }
                        for k in selected_kinds
                    ],
                )
            else:
                annotation["comment"] = (
                    "Navigation parent only. No direct association inferred from its children."
                )
            if tid in parents:
                annotation["showSubtechniques"] = True
            annotations.append(annotation)
        names = " + ".join(KINDS[k] for k in selected_kinds)
        layers[slug] = {
            "name": f"THOR v11 - {names} - ATT&CK {catalog.version}",
            "versions": {
                "attack": catalog.version.split(".")[0],
                "navigator": "5.3.2",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": "Built-in signatures from the supplied export; custom signatures and IOCs excluded. Score 1 means at least one explicit tag maps to an active Enterprise technique. Export-entry counts are metadata, deduplicated per normalized technique within each entry. Revoked IDs are not automatically migrated; no sub-techniques or direct parent scores are inferred. An omitted tactic shows the annotation in all official tactics for that technique. Product loading filters and semantic detection coverage have not been validated.",
            "techniques": annotations,
            "gradient": {
                "colors": ["#f1f5f9", "#2563eb"],
                "minValue": 0,
                "maxValue": 1,
            },
            "legendItems": [
                {"label": "Explicit signature-tag association", "color": "#2563eb"}
            ],
            "metadata": [
                {"name": "Reference ATT&CK collection", "value": catalog.version},
                {"name": "Signature version", "value": signature_version},
                {"name": "Source export SHA256", "value": source_sha256},
                {"name": "Scope", "value": "origin=internal; " + names},
                {
                    "name": "Direct active technique/sub-technique IDs",
                    "value": str(len(direct)),
                },
                {
                    "name": "Counting unit",
                    "value": "One export entry per normalized, explicit technique tag",
                },
            ],
            "sorting": 0,
            "hideDisabled": False,
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
        }
        statistics[slug] = {
            "direct_active_ids": len(direct),
            "direct_parent_ids": sum("." not in t for t in direct),
            "direct_subtechnique_ids": sum("." in t for t in direct),
            "technique_families": len({catalog.parents.get(t, t) for t in direct}),
            "navigation_only_parents": len(parents - direct),
        }
    review = []
    for slug, result in results.items():
        for entry in result["techniques"]:
            if entry["selected_rows"] and entry["status"] != "active_enterprise":
                review.append(
                    {
                        "kind": KINDS[slug],
                        "tag_or_id": entry["technique_id"],
                        "status": entry["status"],
                        "export_entries": entry["selected_rows"],
                        "successors_for_review": "; ".join(
                            s["technique_id"] for s in entry["successors_for_review"]
                        ),
                    }
                )
        for issue in result["tag_issues"]:
            if issue["selected_rows"] and issue["status"] == "malformed_tag":
                review.append(
                    {
                        "kind": KINDS[slug],
                        "tag_or_id": issue["tag"],
                        "status": issue["status"],
                        "export_entries": issue["selected_rows"],
                        "successors_for_review": "",
                    }
                )
    return (
        layers,
        {
            "scope": "Built-in YARA and Sigma; custom signatures and IOCs excluded",
            "layers": statistics,
            "export_scope": {KINDS[k]: r["selected_scope"] for k, r in results.items()},
            "reference_active_ids": sum(
                active(t) for t in catalog.techniques["enterprise-attack"].values()
            ),
        },
        review,
    )


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metadata", type=Path)
    parser.add_argument("--attack-dir", required=True, type=Path)
    parser.add_argument("--attack-version", required=True)
    parser.add_argument(
        "--snapshot-date", required=True, help="Snapshot date, YYYY-MM-DD"
    )
    parser.add_argument("--output-dir", type=Path, default=Path(".local/maps"))
    args = parser.parse_args()
    source = read_json(args.metadata)
    rows = source.get("signatures")
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        parser.error("metadata must contain a signatures list of objects")
    catalog = Catalog(
        {d: args.attack_dir / f"{d}-{args.attack_version}.json" for d in DOMAINS},
        args.attack_version,
    )
    source_sha = fingerprint(args.metadata)
    layers, summary, review = build_layers(
        rows, catalog, source.get("signature_version", "unknown"), source_sha
    )
    for slug, filename in LAYER_FILES.items():
        write_json(args.output_dir / filename, layers[slug])
    provenance = {
        "snapshot_date": args.snapshot_date,
        "source": {
            "file": args.metadata.name,
            "sha256": source_sha,
            "signature_version": source.get("signature_version"),
        },
        "attack_version": catalog.version,
        "reference": catalog.provenance,
        "method": "Explicit active Enterprise tag associations; binary scores; per-entry counts retained as metadata",
        "export_loading_filters": "Not recorded in the source export",
        "semantic_detection_effectiveness_validated": False,
    }
    write_json(args.output_dir / "data/provenance.json", provenance)
    write_json(args.output_dir / "data/mapping-summary.json", summary)
    with (args.output_dir / "data/technique-tag-review.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "kind",
                "tag_or_id",
                "status",
                "export_entries",
                "successors_for_review",
            ],
        )
        writer.writeheader()
        writer.writerows(review)
    print(json.dumps(summary["layers"], indent=2))


if __name__ == "__main__":
    main()

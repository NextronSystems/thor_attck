#!/usr/bin/env python3
"""Audit metadata tags against local MITRE STIX 2.1 bundles; never use a network.

Only aggregate results and ATT&CK IDs are written. Rule names, descriptions,
authors, references, and signature contents are never copied into the reports.
Counts use export rows, once per normalized technique per row. Reused rule IDs
are not assumed to identify duplicate rules. Revocations are review suggestions,
never automatic substitutions in the draft layer.
"""

import argparse
import collections
import csv
import hashlib
import json
from pathlib import Path
import re

TECHNIQUE = re.compile(r"(?:attack\.)?(t\d{4}(?:[._]\d{3})?)", re.I)
TECHNIQUE_LIKE = re.compile(r"(?:attack\.)?t\d", re.I)
DOMAINS = ("enterprise-attack", "mobile-attack", "ics-attack")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def fingerprint(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def external_id(obj):
    return next(
        (
            r["external_id"]
            for r in obj.get("external_references", [])
            if r.get("source_name") == "mitre-attack" and "external_id" in r
        ),
        None,
    )


def active(obj):
    return not (obj.get("revoked", False) or obj.get("x_mitre_deprecated", False))


def object_status(obj):
    return (
        "revoked"
        if obj.get("revoked")
        else "deprecated" if obj.get("x_mitre_deprecated") else "active"
    )


def normalize_tag(raw):
    """Accept complete IDs only; malformed suffixes must never become parents."""
    if not isinstance(raw, str):
        return None
    match = TECHNIQUE.fullmatch(raw.strip())
    return match[1].upper().replace("_", ".") if match else None


class Catalog:
    def __init__(self, bundles, version):
        self.version = version
        self.objects = {}
        self.techniques = {}
        self.provenance = {}
        self.replacements = collections.defaultdict(set)
        self.parents = {}
        self.tactics = {}
        for domain, path in bundles.items():
            data = read_json(path)
            if data.get("type") != "bundle":
                raise ValueError(f"Not a STIX bundle: {path}")
            objects = data["objects"]
            collections_ = [o for o in objects if o["type"] == "x-mitre-collection"]
            expected_name = {
                "enterprise-attack": "Enterprise ATT&CK",
                "mobile-attack": "Mobile ATT&CK",
                "ics-attack": "ICS ATT&CK",
            }[domain]
            if (
                len(collections_) != 1
                or collections_[0].get("x_mitre_version") != version
                or collections_[0].get("name") != expected_name
            ):
                raise ValueError(
                    f"Wrong domain or collection version: {path}; expected {domain} {version}"
                )
            self.provenance[domain] = {
                "file": Path(path).name,
                "sha256": fingerprint(path),
                "collection_version": collections_[0]["x_mitre_version"],
                "collection_modified": collections_[0].get("modified"),
                "source": f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}-{version}.json",
            }
            # Some STIX bundles contain multiple versions of one object.
            latest = {}
            for obj in objects:
                if obj.get("modified", "") >= latest.get(obj["id"], {}).get(
                    "modified", ""
                ):
                    latest[obj["id"]] = obj
            self.objects.update(latest)
            self.techniques[domain] = {
                external_id(o): o
                for o in latest.values()
                if o["type"] == "attack-pattern" and external_id(o)
            }
            if domain == "enterprise-attack":
                tactics_by_id = {
                    o["id"]: o
                    for o in latest.values()
                    if o["type"] == "x-mitre-tactic" and active(o)
                }
                matrices = [
                    o
                    for o in latest.values()
                    if o["type"] == "x-mitre-matrix" and active(o)
                ]
                for matrix in matrices:
                    for ref in matrix.get("tactic_refs", []):
                        tactic = tactics_by_id[ref]
                        self.tactics[tactic["x_mitre_shortname"]] = {
                            "id": external_id(tactic),
                            "name": tactic["name"],
                        }
        for obj in self.objects.values():
            if obj["type"] != "relationship" or not active(obj):
                continue
            if obj.get("relationship_type") == "revoked-by":
                self.replacements[obj["source_ref"]].add(obj["target_ref"])
            if obj.get("relationship_type") == "subtechnique-of":
                child = external_id(self.objects.get(obj["source_ref"], {}))
                parent = external_id(self.objects.get(obj["target_ref"], {}))
                if child and parent:
                    self.parents[child] = parent

    def classify(self, tid):
        obj = self.techniques["enterprise-attack"].get(tid)
        if obj:
            return object_status(obj) + "_enterprise"
        return (
            "other_domain"
            if any(tid in self.techniques[d] for d in DOMAINS[1:])
            else "unknown_id"
        )

    def successors(self, tid):
        """Follow revoked-by chains, preserving all terminal branches for review."""
        start = self.techniques["enterprise-attack"].get(tid, {}).get("id")
        seen, result = set(), []

        def visit(ref, chain):
            if ref in seen:
                return
            seen.add(ref)
            obj = self.objects.get(ref, {})
            next_refs = sorted(self.replacements.get(ref, ()))
            if next_refs:
                for next_ref in next_refs:
                    visit(next_ref, chain + [external_id(obj)])
            elif chain and external_id(obj):
                result.append(
                    {
                        "technique_id": external_id(obj),
                        "name": obj.get("name"),
                        "status": object_status(obj),
                        "chain": chain + [external_id(obj)],
                    }
                )

        if start:
            visit(start, [])
        return result


def summarize_rows(rows, catalog):
    valid_rows, tagged_rows, no_tags = set(), set(), 0
    statuses = collections.defaultdict(set)
    techniques = set()
    for index, row in rows:
        tags = row.get("tags", [])
        no_tags += not bool(tags)
        for raw in tags:
            tid = normalize_tag(raw)
            if tid:
                tagged_rows.add(index)
                status = catalog.classify(tid)
                statuses[status].add(index)
                if status == "active_enterprise":
                    valid_rows.add(index)
                    techniques.add(tid)
    return {
        "rows": len(rows),
        "rows_without_tags": no_tags,
        "rows_with_technique_id": len(tagged_rows),
        "rows_with_active_enterprise_id": len(valid_rows),
        "distinct_active_enterprise_ids": len(techniques),
        "rows_by_status_overlapping": {k: len(v) for k, v in sorted(statuses.items())},
    }


def audit(rows, catalog, origin="internal", kind="YARA Rule"):
    tag_rows = collections.defaultdict(set)
    normalized_rows = collections.defaultdict(set)
    issue_rows = collections.defaultdict(set)
    tactic_tags = collections.Counter()
    normalization = collections.Counter()
    for index, row in enumerate(rows):
        tags = row.get("tags", [])
        if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
            raise ValueError(f"tags must be a list of strings (export row {index + 1})")
        for raw in set(tags):
            tag = raw.strip()
            tid = normalize_tag(raw)
            if tid:
                tag_rows[raw].add(index)
                normalized_rows[tid].add(index)
                if tag != tid:
                    normalization["row_tag_pairs_requiring_normalization"] += 1
                if "_" in tag:
                    normalization["row_tag_pairs_with_underscore"] += 1
                if tag.lower().startswith("attack."):
                    normalization["row_tag_pairs_with_attack_prefix"] += 1
                if tag != tag.upper():
                    normalization["row_tag_pairs_with_lowercase"] += 1
            elif TECHNIQUE_LIKE.match(tag):
                issue_rows[(raw, "malformed_tag")].add(index)
            elif tag.lower().startswith("attack."):
                if tag.lower()[7:] in catalog.tactics:
                    tactic_tags[tag] += 1
                else:
                    issue_rows[(raw, "unknown_attack_tag")].add(index)

    all_rows = list(enumerate(rows))
    selected = {
        i
        for i, row in all_rows
        if row.get("origin") == origin and row.get("kind") == kind
    }
    selected_rows = [(i, row) for i, row in all_rows if i in selected]
    entries, direct_rows = [], {}
    enterprise = catalog.techniques["enterprise-attack"]
    for tid, indices in sorted(normalized_rows.items()):
        status = catalog.classify(tid)
        obj = enterprise.get(tid, {})
        other = [
            {
                "domain": domain,
                "name": catalog.techniques[domain][tid]["name"],
                "status": object_status(catalog.techniques[domain][tid]),
            }
            for domain in DOMAINS[1:]
            if tid in catalog.techniques[domain]
        ]
        entries.append(
            {
                "technique_id": tid,
                "name": obj.get("name"),
                "status": status,
                "all_rows": len(indices),
                "selected_rows": len(indices & selected),
                "raw_tags": sorted(
                    raw for raw in tag_rows if normalize_tag(raw) == tid
                ),
                "successors_for_review": catalog.successors(tid),
                "other_domains": other,
                "tactics": sorted(
                    p["phase_name"]
                    for p in obj.get("kill_chain_phases", [])
                    if p["kill_chain_name"] == "mitre-attack"
                ),
                "created": obj.get("created"),
            }
        )
        if status == "active_enterprise" and indices & selected:
            direct_rows[tid] = indices & selected

    groups = []
    for group_origin, group_kind in sorted(
        {(r.get("origin", ""), r.get("kind", "")) for r in rows}
    ):
        group_rows = [
            (i, r)
            for i, r in all_rows
            if r.get("origin", "") == group_origin and r.get("kind", "") == group_kind
        ]
        groups.append(
            {
                "origin": group_origin,
                "kind": group_kind,
                **summarize_rows(group_rows, catalog),
            }
        )
    status_counts = collections.Counter(e["status"] for e in entries)
    assignments = collections.Counter()
    for entry in entries:
        assignments[entry["status"]] += entry["all_rows"]
    rollup = collections.defaultdict(set)
    for tid, indices in direct_rows.items():
        rollup[catalog.parents.get(tid, tid)].update(indices)
    issues = [
        {
            "tag": tag,
            "status": status,
            "all_rows": len(indices),
            "selected_rows": len(indices & selected),
        }
        for (tag, status), indices in sorted(issue_rows.items())
    ]
    identity = {}
    for key in ("id", "rule_name"):
        counter = collections.Counter(r[key] for r in rows if r.get(key))
        identity[key] = {
            "present_rows": sum(counter.values()),
            "distinct_values": len(counter),
            "duplicate_values": sum(n > 1 for n in counter.values()),
            "extra_rows_reusing_value": sum(n - 1 for n in counter.values()),
        }
    return {
        "summary": summarize_rows(all_rows, catalog),
        "groups": groups,
        "selected_scope": {
            "origin": origin,
            "kind": kind,
            **summarize_rows(selected_rows, catalog),
        },
        "normalization": dict(normalization),
        "unique_ids_by_status": dict(status_counts),
        "row_technique_assignments_by_status": dict(assignments),
        "identity": identity,
        "techniques": entries,
        "tag_issues": issues,
        "tactic_only_tags": dict(tactic_tags),
        "selected_direct_counts": {k: len(v) for k, v in sorted(direct_rows.items())},
        "selected_parent_family_counts": {k: len(v) for k, v in sorted(rollup.items())},
    }


def make_layer(result, catalog):
    scope = result["selected_scope"]
    counts = result["selected_direct_counts"]
    # Parent rows expose children without inventing direct parent coverage.
    parents = {catalog.parents[t] for t in counts if t in catalog.parents}
    techniques = []
    for tid in sorted(set(counts) | parents):
        annotation = {"techniqueID": tid, "enabled": True}
        if tid in counts:
            annotation.update(
                score=counts[tid],
                comment="Export entries explicitly tagged with this active technique. Metadata association; detection effectiveness and tactical context have not been validated.",
            )
        else:
            annotation["comment"] = (
                "Navigation parent only; no direct tag count. Expand to see tagged sub-techniques."
            )
        if tid in parents:
            annotation["showSubtechniques"] = True
        techniques.append(annotation)
    return {
        "name": f"DRAFT - THOR metadata tag counts ({scope['origin']} / {scope['kind']})",
        # Navigator identifies releases by major version. Preserve the exact
        # reference collection separately in metadata and the audit hashes.
        "versions": {
            "attack": catalog.version.split(".")[0],
            "navigator": "5.3.2",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": f"DRAFT: {scope['origin']} / {scope['kind']}; counts of export entries, once per normalized technique per entry. Only active Enterprise IDs; no revoked-ID migration, no inferred sub-techniques. An omitted tactic applies the annotation to all official tactics for that technique, not proof of detection in every tactic. No platform restriction is inferred from technique metadata. Tag frequency is not a detection coverage percentage. Private local review artifact.",
        "sorting": 0,
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#eff6ff", "#1d4ed8"],
            "minValue": 0,
            "maxValue": max(1, max(counts.values(), default=0)),
        },
        "metadata": [
            {
                "name": "Status",
                "value": "Draft: tag validity checked; semantic correctness not validated",
            },
            {"name": "Reference ATT&CK collection", "value": catalog.version},
            {
                "name": "Counting unit",
                "value": "One export row per explicitly tagged technique; no parent aggregation",
            },
            {
                "name": "Scope",
                "value": f"origin={scope['origin']}; kind={scope['kind']}",
            },
        ],
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def review_old_layer(path, catalog):
    old = read_json(path)
    annotations = []
    for annotation in old.get("techniques", []):
        tid, tactic = annotation["techniqueID"], annotation.get("tactic")
        obj = catalog.techniques["enterprise-attack"].get(tid, {})
        current_tactics = [
            p["phase_name"]
            for p in obj.get("kill_chain_phases", [])
            if p["kill_chain_name"] == "mitre-attack"
        ]
        annotations.append(
            {
                "technique_id": tid,
                "old_tactic": tactic,
                "status": catalog.classify(tid),
                "tactic_exists_today": tactic in catalog.tactics,
                "tactic_matches_current_technique": tactic in current_tactics,
                "successors_for_review": catalog.successors(tid),
            }
        )
    unique = {x["technique_id"]: x["status"] for x in annotations}
    return {
        "file": Path(path).name,
        "sha256": fingerprint(path),
        "layer_version": old.get("version"),
        "domain": old.get("domain"),
        "annotation_rows": len(annotations),
        "distinct_ids": len(unique),
        "unique_ids_by_status": dict(collections.Counter(unique.values())),
        "annotation_rows_with_obsolete_tactic": sum(
            not a["tactic_exists_today"] for a in annotations
        ),
        "annotations": annotations,
    }


def write_csv(path, fields, rows):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_results(result, catalog, output):
    output.mkdir(parents=True, exist_ok=True)
    (output / "audit.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (output / "draft-navigator.json").write_text(
        json.dumps(make_layer(result, catalog), indent=2) + "\n", encoding="utf-8"
    )
    review = []
    for entry in result["techniques"]:
        if entry["status"] != "active_enterprise":
            review.append(
                {
                    "tag_or_id": entry["technique_id"],
                    "status": entry["status"],
                    "all_rows": entry["all_rows"],
                    "selected_rows": entry["selected_rows"],
                    "official_successor_chains_for_review": "; ".join(
                        " -> ".join(s["chain"]) for s in entry["successors_for_review"]
                    ),
                    "other_domains": "; ".join(
                        d["domain"] + ": " + d["name"] for d in entry["other_domains"]
                    ),
                }
            )
    review.extend(
        {
            "tag_or_id": i["tag"],
            "status": i["status"],
            "all_rows": i["all_rows"],
            "selected_rows": i["selected_rows"],
            "official_successor_chains_for_review": "",
            "other_domains": "",
        }
        for i in result["tag_issues"]
    )
    write_csv(
        output / "tag-review.csv",
        [
            "tag_or_id",
            "status",
            "all_rows",
            "selected_rows",
            "official_successor_chains_for_review",
            "other_domains",
        ],
        review,
    )
    write_csv(
        output / "technique-counts.csv",
        ["technique_id", "name", "tactics", "direct_count", "parent_family_count"],
        [
            {
                "technique_id": t,
                "name": catalog.techniques["enterprise-attack"][t]["name"],
                "tactics": "; ".join(
                    p["phase_name"]
                    for p in catalog.techniques["enterprise-attack"][t].get(
                        "kill_chain_phases", []
                    )
                    if p["kill_chain_name"] == "mitre-attack"
                ),
                "direct_count": result["selected_direct_counts"].get(t, 0),
                "parent_family_count": result["selected_parent_family_counts"].get(
                    t, ""
                ),
            }
            for t in sorted(
                set(result["selected_direct_counts"])
                | set(result["selected_parent_family_counts"])
            )
        ],
    )
    scope = result["selected_scope"]
    lines = [
        "THOR / MITRE ATT&CK metadata audit",
        "=" * 36,
        f"Reference: Enterprise, Mobile and ICS ATT&CK {catalog.version} (STIX 2.1).",
        f"Export: {result['source']['file']}; signature version: {result['source']['signature_version']}.",
        f"Export rows: {result['summary']['rows']:,}",
        f"Rows with active Enterprise IDs: {result['summary']['rows_with_active_enterprise_id']:,}",
        f"Distinct active Enterprise IDs: {result['summary']['distinct_active_enterprise_ids']}",
        "ID statuses: " + json.dumps(result["unique_ids_by_status"]),
        "",
        f"Selected scope: origin={scope['origin']}; kind={scope['kind']}",
        f"Selected rows: {scope['rows']}; directly tagged active IDs: {scope['distinct_active_enterprise_ids']}",
        "",
        "Origin | Kind | Rows | Without tags | With technique ID | With active Enterprise ID",
    ]
    lines.extend(
        f"{g['origin']} | {g['kind']} | {g['rows']} | {g['rows_without_tags']} | {g['rows_with_technique_id']} | {g['rows_with_active_enterprise_id']}"
        for g in result["groups"]
    )
    lines.extend(
        [
            "",
            "Method:",
            "- The audit layer score counts export entries per normalized explicit technique tag.",
            "- Each entry contributes at most once to each technique. Parent-family counts are separate.",
            "- Navigation parents have no inferred direct score. No revoked ID is automatically migrated.",
            "- An omitted tactic displays the association in every official tactic for that technique.",
            "- These metadata associations do not establish detection effectiveness or full coverage.",
            "- The export does not record loading filters or the tagger catalog version.",
            "",
            "Outputs:",
            "- audit.json: aggregate results and source SHA256 hashes.",
            "- tag-review.csv: invalid, obsolete and other-domain IDs with official successor chains.",
            "- technique-counts.csv: direct counts and separate parent-family counts.",
            "- draft-navigator.json: count-based audit layer; use build_maps.py for the presence-based published layers.",
        ]
    )
    if "old_layer" in result:
        old = result["old_layer"]
        lines.extend(
            [
                "",
                "Historical layer:",
                f"{old['annotation_rows']} annotations; {old['distinct_ids']} distinct IDs.",
                "Current ID statuses: " + json.dumps(old["unique_ids_by_status"]),
                "Historical scores and export-entry counts use different methods.",
            ]
        )
    (output / "audit.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metadata", type=Path)
    parser.add_argument("--attack-dir", type=Path, required=True)
    parser.add_argument("--attack-version", required=True)
    parser.add_argument("--old-layer", type=Path)
    parser.add_argument("--origin", default="internal")
    parser.add_argument("--kind", default="YARA Rule")
    parser.add_argument("--output", type=Path, default=Path(".local/audit"))
    args = parser.parse_args()
    catalog = Catalog(
        {d: args.attack_dir / f"{d}-{args.attack_version}.json" for d in DOMAINS},
        args.attack_version,
    )
    data = read_json(args.metadata)
    rows = data.get("signatures")
    if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
        parser.error("metadata must contain a signatures list of objects")
    result = audit(rows, catalog, args.origin, args.kind)
    result["source"] = {
        "file": args.metadata.name,
        "sha256": fingerprint(args.metadata),
        "signature_version": data.get("signature_version"),
    }
    result["reference"] = {
        "attack_version": catalog.version,
        "bundles": catalog.provenance,
        "active_enterprise_techniques_including_subtechniques": sum(
            active(o) for o in catalog.techniques["enterprise-attack"].values()
        ),
        "tactics": catalog.tactics,
    }
    result["method"] = {
        "unit": "Export row, once per normalized technique ID per row",
        "status_row_counts_overlap": True,
        "revoked_ids_automatically_migrated": False,
        "semantic_correctness_validated": False,
        "network_used": False,
        "scope_note": "Draft scope is a review choice; product inclusion and scan modes must be confirmed before publication.",
    }
    if args.old_layer:
        result["old_layer"] = review_old_layer(args.old_layer, catalog)
    write_results(result, catalog, args.output)
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "summary",
                    "selected_scope",
                    "unique_ids_by_status",
                    "tag_issues",
                )
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

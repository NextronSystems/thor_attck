"""Synthetic fixtures: no private signature metadata and no network access."""

import json
from pathlib import Path
import tempfile
import unittest

from tools.audit_attack import Catalog, DOMAINS, audit, make_layer, normalize_tag


def technique(tid, **extra):
    return {
        "type": "attack-pattern",
        "id": "attack-pattern--" + tid,
        "name": tid,
        "modified": "2026-01-01",
        "created": "2020-01-01",
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
        ],
        **extra,
    }


def relation(source, target, kind):
    return {
        "type": "relationship",
        "id": f"relationship--{source}-{target}-{kind}",
        "relationship_type": kind,
        "source_ref": "attack-pattern--" + source,
        "target_ref": "attack-pattern--" + target,
    }


class AuditTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = {}
        names = ["Enterprise ATT&CK", "Mobile ATT&CK", "ICS ATT&CK"]
        self.extra = [
            technique("T1059"),
            technique("T1059.001"),
            technique("T1086", revoked=True),
            technique("T1000", revoked=True),
            technique("T1001", x_mitre_deprecated=True),
            relation("T1059.001", "T1059", "subtechnique-of"),
            relation("T1000", "T1086", "revoked-by"),
            relation("T1086", "T1059.001", "revoked-by"),
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--exec",
                "name": "Execution",
                "x_mitre_shortname": "execution",
            },
            {
                "type": "x-mitre-matrix",
                "id": "x-mitre-matrix--ent",
                "tactic_refs": ["x-mitre-tactic--exec"],
            },
        ]
        for domain, name in zip(DOMAINS, names):
            objects = [
                {
                    "type": "x-mitre-collection",
                    "id": "x-mitre-collection--" + domain,
                    "name": name,
                    "x_mitre_version": "20.0",
                }
            ]
            objects += (
                self.extra if domain == "enterprise-attack" else [technique("T0830")]
            )
            path = Path(self.temp.name) / (domain + ".json")
            path.write_text(json.dumps({"type": "bundle", "objects": objects}))
            self.paths[domain] = path
        self.catalog = Catalog(self.paths, "20.0")

    def row(self, tags, **extra):
        return {"origin": "internal", "kind": "YARA Rule", "tags": tags, **extra}

    def test_normalization_rejects_partial_ids(self):
        self.assertEqual(normalize_tag("attack.t1059_001"), "T1059.001")
        for raw in [
            "T1069_00",
            "T1059.0001",
            "T1059_001_extra",
            "prefix_T1059",
            "T1059.abc",
        ]:
            self.assertIsNone(normalize_tag(raw), raw)

    def test_scope_and_one_count_per_row_technique(self):
        rows = [
            self.row(["T1059_001", "attack.t1059.001", "T1059_001"]),
            self.row(["T1059.001"], origin="custom"),
            self.row(["T1059.001"], kind="Hash IOC"),
            self.row([], kind="Sigma Rule"),
        ]
        result = audit(rows, self.catalog)
        self.assertEqual(result["selected_direct_counts"], {"T1059.001": 1})
        self.assertEqual(result["summary"]["rows_with_active_enterprise_id"], 3)
        self.assertEqual(result["techniques"][0]["all_rows"], 3)

    def test_revoked_chains_are_review_only(self):
        result = audit([self.row(["T1000", "T1086"])], self.catalog)
        self.assertEqual(result["selected_direct_counts"], {})
        self.assertEqual(
            result["summary"]["rows_by_status_overlapping"]["revoked_enterprise"], 1
        )
        successor = next(
            t for t in result["techniques"] if t["technique_id"] == "T1000"
        )["successors_for_review"][0]
        self.assertEqual(successor["chain"], ["T1000", "T1086", "T1059.001"])
        self.assertEqual(successor["status"], "active")

    def test_domains_and_invalid_tags_do_not_inflate_layer(self):
        result = audit(
            [self.row(["T0830", "T9999", "T1069_00", "T1001", "attack.execution"])],
            self.catalog,
        )
        self.assertEqual(
            result["unique_ids_by_status"],
            {"other_domain": 1, "unknown_id": 1, "deprecated_enterprise": 1},
        )
        self.assertEqual(result["tag_issues"][0]["status"], "malformed_tag")
        self.assertEqual(result["tactic_only_tags"], {"attack.execution": 1})
        self.assertEqual(make_layer(result, self.catalog)["techniques"], [])

    def test_parent_union_does_not_double_count_or_invent_direct_score(self):
        result = audit(
            [self.row(["T1059", "T1059.001"]), self.row(["T1059.001"])], self.catalog
        )
        self.assertEqual(result["selected_direct_counts"], {"T1059": 1, "T1059.001": 2})
        self.assertEqual(result["selected_parent_family_counts"], {"T1059": 2})
        result = audit([self.row(["T1059.001"])], self.catalog)
        parent = next(
            t
            for t in make_layer(result, self.catalog)["techniques"]
            if t["techniqueID"] == "T1059"
        )
        self.assertNotIn("score", parent)
        self.assertTrue(parent["showSubtechniques"])
        self.assertEqual(make_layer(result, self.catalog)["versions"]["attack"], "20")

    def test_reused_rule_ids_are_not_silently_deduplicated(self):
        result = audit(
            [self.row(["T1059"], id="reused"), self.row(["T1059"], id="reused")],
            self.catalog,
        )
        self.assertEqual(result["selected_direct_counts"]["T1059"], 2)
        self.assertEqual(result["identity"]["id"]["extra_rows_reusing_value"], 1)

    def test_bundle_version_must_match(self):
        with self.assertRaisesRegex(ValueError, "Wrong domain or collection version"):
            Catalog(self.paths, "19.2")

    def test_latest_stix_object_wins(self):
        path = self.paths["enterprise-attack"]
        data = json.loads(path.read_text())
        data["objects"].append(technique("T1059", modified="2025-01-01", revoked=True))
        path.write_text(json.dumps(data))
        self.assertEqual(
            Catalog(self.paths, "20.0").classify("T1059"), "active_enterprise"
        )


if __name__ == "__main__":
    unittest.main()

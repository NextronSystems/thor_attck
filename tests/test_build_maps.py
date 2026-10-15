import json
from pathlib import Path
import tempfile
import unittest

from tools.audit_attack import Catalog, DOMAINS
from tools.build_maps import build_layers


class BuildMapsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        objects = []
        for tid in ("T1059", "T1059.001", "T1086"):
            objects.append(
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--" + tid,
                    "name": tid,
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": tid}
                    ],
                    "revoked": tid == "T1086",
                }
            )
        objects.append(
            {
                "type": "relationship",
                "id": "relationship--parent",
                "relationship_type": "subtechnique-of",
                "source_ref": "attack-pattern--T1059.001",
                "target_ref": "attack-pattern--T1059",
            }
        )
        paths = {}
        for domain, name in zip(
            DOMAINS, ("Enterprise ATT&CK", "Mobile ATT&CK", "ICS ATT&CK")
        ):
            path = Path(self.temp.name) / (domain + ".json")
            collection = {
                "type": "x-mitre-collection",
                "id": "x-mitre-collection--" + domain,
                "name": name,
                "x_mitre_version": "20.0",
            }
            path.write_text(
                json.dumps(
                    {
                        "type": "bundle",
                        "objects": [collection]
                        + (objects if domain == "enterprise-attack" else []),
                    }
                )
            )
            paths[domain] = path
        self.catalog = Catalog(paths, "20.0")

    def build(self, rows):
        return build_layers(rows, self.catalog, "test-revision", "0" * 64)

    def row(self, tags, kind="YARA Rule", origin="internal"):
        return {"tags": tags, "kind": kind, "origin": origin}

    def test_combined_union_preserves_source_counts_and_aliases(self):
        layers, summary, _ = self.build(
            [
                self.row(["T1059_001", "attack.t1059.001", "T1059_001"]),
                self.row(["attack.t1059.001"], "Sigma Rule"),
            ]
        )
        child = next(
            t
            for t in layers["combined"]["techniques"]
            if t["techniqueID"] == "T1059.001"
        )
        self.assertEqual(child["score"], 1)
        self.assertEqual([m["value"] for m in child["metadata"]], ["1", "1"])
        self.assertEqual(summary["layers"]["combined"]["direct_active_ids"], 1)
        self.assertEqual(summary["layers"]["combined"]["technique_families"], 1)

    def test_scope_excludes_custom_signatures_and_iocs(self):
        layers, summary, _ = self.build(
            [self.row(["T1059"], origin="custom"), self.row(["T1059"], "Hash IOC")]
        )
        self.assertEqual(layers["combined"]["techniques"], [])
        self.assertEqual(summary["layers"]["combined"]["direct_active_ids"], 0)

    def test_navigation_parent_has_no_invented_score(self):
        layers, _, _ = self.build([self.row(["T1059_001"])])
        parent = next(
            t for t in layers["combined"]["techniques"] if t["techniqueID"] == "T1059"
        )
        self.assertNotIn("score", parent)
        self.assertTrue(parent["showSubtechniques"])

    def test_revoked_and_malformed_ids_are_review_items(self):
        layers, _, review = self.build(
            [self.row(["T1086", "T1059_00", "attack.execution"])]
        )
        self.assertEqual(layers["combined"]["techniques"], [])
        self.assertEqual(
            {r["status"] for r in review}, {"revoked_enterprise", "malformed_tag"}
        )

    def test_layers_do_not_copy_rule_identities(self):
        row = dict(
            self.row(["T1059"]),
            rule_name="identity-canary",
            description="private-description",
            id="source-rule-id",
        )
        layers, summary, review = self.build([row])
        output = json.dumps([layers, summary, review])
        for value in ("identity-canary", "private-description", "source-rule-id"):
            self.assertNotIn(value, output)


if __name__ == "__main__":
    unittest.main()

import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SnapshotTest(unittest.TestCase):
    def test_source_export_matches_provenance(self):
        provenance = json.loads((ROOT / "data/provenance.json").read_text())
        source = ROOT / "data" / provenance["source"]["file"]
        self.assertEqual(
            hashlib.sha256(source.read_bytes()).hexdigest(),
            provenance["source"]["sha256"],
        )
        self.assertEqual(
            json.loads(source.read_text())["signature_version"],
            provenance["source"]["signature_version"],
        )

    def test_combined_layer_is_exact_union_of_separate_layers(self):
        layers = [
            json.loads((ROOT / filename).read_text())
            for filename in (
                "THOR_APT_Scanner.json",
                "layers/THOR_APT_Scanner_yara.json",
                "layers/THOR_APT_Scanner_sigma.json",
            )
        ]
        sets = []
        for layer in layers:
            self.assertEqual(layer["domain"], "enterprise-attack")
            self.assertEqual(
                len(layer["techniques"]),
                len({t["techniqueID"] for t in layer["techniques"]}),
            )
            self.assertTrue(
                all(t["score"] == 1 for t in layer["techniques"] if "score" in t)
            )
            sets.append(
                {t["techniqueID"] for t in layer["techniques"] if t.get("score") == 1}
            )
        self.assertEqual(sets[0], sets[1] | sets[2])


if __name__ == "__main__":
    unittest.main()

"""Render reproducible snapshot images from generated layers and pinned local STIX data."""

from pathlib import Path
from collections import Counter
import json
import sys
import textwrap
from xml.sax.saxutils import escape
import importlib.metadata
import argparse
import subprocess

parser = argparse.ArgumentParser(
    description="Render the published layers using MITRE's exporter and our own SVG overview."
)
parser.add_argument("--attack-dir", type=Path, required=True)
parser.add_argument("--attack-version", required=True)
parser.add_argument("--output-dir", type=Path, default=Path("."))
parser.add_argument(
    "--legacy-layer",
    type=Path,
    default=Path(__file__).resolve().parents[1] / "archive/THOR_APT_Scanner.json",
)
parser.add_argument(
    "--png", action="store_true", help="Also render PNGs; requires rsvg-convert"
)
args = parser.parse_args()
ROOT = args.output_dir
OUT = ROOT / "img"
OUT.mkdir(parents=True, exist_ok=True)
(ROOT / "data").mkdir(parents=True, exist_ok=True)
(ROOT / ".local").mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit_attack as a

provenance = json.loads((ROOT / "data/provenance.json").read_text())
version = args.attack_version
if provenance["attack_version"] != version:
    parser.error("ATT&CK version does not match the layer provenance")
revision = provenance["source"]["signature_version"]
catalog = a.Catalog(
    {d: args.attack_dir / f"{d}-{version}.json" for d in a.DOMAINS}, version
)
layers = {
    k: json.loads((ROOT / filename).read_text())
    for k, filename in {
        "combined": "THOR_APT_Scanner.json",
        "yara": "layers/THOR_APT_Scanner_yara.json",
        "sigma": "layers/THOR_APT_Scanner_sigma.json",
    }.items()
}
sets = {
    k: {t["techniqueID"] for t in layer["techniques"] if t.get("score", 0) > 0}
    for k, layer in layers.items()
}
old = json.loads(args.legacy_layer.read_text())
oldids = {t["techniqueID"] for t in old["techniques"] if t.get("score", 0) > 0}
activeold = {t for t in oldids if catalog.classify(t) == "active_enterprise"}
families = {catalog.parents.get(t, t) for t in sets["combined"]}
missing = sorted(activeold - families)
comparison = {
    "reference": "Enterprise ATT&CK " + version,
    "old": {
        "distinct_parent_ids": len(oldids),
        "status_in_current_catalog": dict(Counter(catalog.classify(t) for t in oldids)),
        "score_distribution": dict(Counter(t["score"] for t in old["techniques"])),
    },
    "new": {
        "direct_technique_and_subtechnique_ids": len(sets["combined"]),
        "families": len(families),
        "direct_parent_ids": sum("." not in t for t in sets["combined"]),
        "direct_subtechnique_ids": sum("." in t for t in sets["combined"]),
    },
    "active_old_ids_represented_directly": len(activeold & sets["combined"]),
    "active_old_ids_represented_by_family": len(activeold & families),
    "active_old_ids_without_current_family_association": [
        {"id": t, "name": catalog.techniques["enterprise-attack"][t]["name"]}
        for t in missing
    ],
    "warning": "Historical scored parent-level layer and current explicit tag associations are not equivalent measures of detection effectiveness.",
}
rows = []
for tactic, meta in catalog.tactics.items():
    allids = {
        tid
        for tid, obj in catalog.techniques["enterprise-attack"].items()
        if a.active(obj)
        and any(
            p["phase_name"] == tactic and p["kill_chain_name"] == "mitre-attack"
            for p in obj.get("kill_chain_phases", [])
        )
    }
    yara, sigma = allids & sets["yara"], allids & sets["sigma"]
    rows.append(
        {
            "tactic": tactic,
            "name": meta["name"],
            "total": len(allids),
            "both": len(yara & sigma),
            "yara": len(yara - sigma),
            "sigma": len(sigma - yara),
            "associated": len(yara | sigma),
        }
    )
comparison["tactics"] = rows
(ROOT / "data/mapping-comparison.json").write_text(
    json.dumps(comparison, indent=2) + "\n"
)

# Own renderer: source attribution and a modern overview, without implied strength scores.
W, H = 2100, 1740
parts = [
    f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
    '<rect width="100%" height="100%" fill="#f3f6fa"/>',
    "<style>text{font-family:Arial,Helvetica,sans-serif} .muted{fill:#64748b}</style>",
]


def rect(x, y, w, h, fill, r=0, stroke=None):
    parts.append(
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}"'
        + (f' stroke="{stroke}"' if stroke else "")
        + "/>"
    )


def text(x, y, value, size=22, fill="#17243b", weight=400, anchor="start"):
    parts.append(
        f'<text x="{x}" y="{y}" font-size="{size}" fill="{fill}" font-weight="{weight}" text-anchor="{anchor}">{escape(str(value))}</text>'
    )


def wrapped(x, y, value, width=70, size=22, fill="#64748b", line=30, weight=400):
    for n, linevalue in enumerate(textwrap.wrap(value, width=width)):
        text(x, y + n * line, linevalue, size, fill, weight)
    return y + len(textwrap.wrap(value, width=width)) * line


rect(0, 0, W, 275, "#101d34")
rect(60, 53, 9, 51, "#38bdf8", 4)
text(92, 93, "THOR  /  ATT&CK mapping", 49, "#ffffff", 700)
text(
    92,
    141,
    f"Built-in YARA + Sigma signatures · Enterprise ATT&CK v{version}",
    27,
    "#cbd5e1",
)
text(
    92,
    191,
    f'Signature snapshot {revision}  |  {provenance["snapshot_date"]}',
    21,
    "#94a3b8",
)
text(
    92,
    236,
    "Explicit signature-tag associations. Detection effectiveness has not been validated.",
    21,
    "#94a3b8",
)

cards = [
    (
        str(len(sets["combined"])),
        "direct technique IDs",
        f"{sum('.' not in t for t in sets['combined'])} parents + {sum('.' in t for t in sets['combined'])} sub-techniques",
    ),
    (str(len(families)), "technique families", "Parents with a direct or child tag"),
    (
        str(len(sets["yara"])),
        "YARA-associated IDs",
        f"{len(sets['sigma'])} Sigma-associated IDs",
    ),
    (
        f"{len(activeold&families)} / {len(activeold)}",
        "active old IDs represented",
        "Directly or through sub-techniques",
    ),
]
for i, (number, label, note) in enumerate(cards):
    x = 60 + i * 500
    rect(x, 310, 480, 170, "#ffffff", 16)
    text(x + 27, 371, number, 48, "#0f294f", 700)
    text(x + 27, 414, label, 23, "#233952", 600)
    text(x + 27, 452, note, 18, "#64748b")

rect(60, 515, 1980, 825, "#ffffff", 18)
text(90, 562, "Where the exported signatures map", 30, "#17243b", 700)
text(
    90,
    600,
    "Each bar spans all active technique and sub-technique IDs in that tactic.",
    21,
    "#64748b",
)
colors = {"both": "#2563eb", "yara": "#8b5cf6", "sigma": "#0891b2", "none": "#e8edf4"}
for x, key, label in [
    (90, "both", "YARA + Sigma"),
    (355, "yara", "YARA only"),
    (575, "sigma", "Sigma only"),
    (800, "none", "No explicit tag association"),
]:
    rect(x, 625, 19, 19, colors[key], 4)
    text(x + 30, 642, label, 19)
text(1958, 642, "Tagged / active IDs", 18, "#64748b", 400, "end")
barx, barw = 480, 1160
for i, row in enumerate(rows):
    y = 684 + i * 40
    text(90, y + 23, row["name"], 22, "#233952", 500)
    rect(barx, y, barw, 28, colors["none"], 6)
    offset = 0
    for key in ("both", "yara", "sigma"):
        width = barw * row[key] / row["total"]
        if width:
            rect(barx + offset, y, width, 28, colors[key])
        offset += width
    text(
        1815, y + 22, f"{row['associated']} / {row['total']}", 22, "#17243b", 600, "end"
    )
    text(
        1960,
        y + 22,
        f"{100*row['associated']/row['total']:.0f}%",
        21,
        "#64748b",
        400,
        "end",
    )
text(
    90,
    1310,
    "A technique can belong to several tactics; row totals must not be added together.",
    18,
    "#64748b",
)

rect(60, 1375, 965, 240, "#ffffff", 18)
text(90, 1422, "Compared with the historical map", 27, "#17243b", 700)
text(
    90,
    1467,
    f"{len(oldids)} legacy parent IDs → {len(families)} current technique families",
    25,
    "#0f294f",
    600,
)
wrapped(
    90,
    1508,
    f"{len(oldids-activeold)} historical IDs are now revoked or deprecated. The old scores and current tag presence use different methods.",
    70,
    21,
    line=30,
)
text(
    90,
    1588,
    "These figures do not establish a change in detection quality.",
    20,
    "#64748b",
)

rect(1055, 1375, 985, 240, "#ffffff", 18)
text(1085, 1422, f"{len(missing)} current IDs need follow-up", 27, "#17243b", 700)
for i, tid in enumerate(missing[:4]):
    obj = catalog.techniques["enterprise-attack"][tid]
    text(1085, 1462 + i * 34, f"{tid}  {obj['name']}", 21, "#334155")
text(
    60,
    1670,
    f"Sources: official MITRE STIX {version} + THOR export. Custom signatures and IOCs excluded.",
    20,
    "#64748b",
)
text(
    60,
    1704,
    "Produced with our own renderer · Presence is shown consistently; no score implies full technique coverage.",
    19,
    "#64748b",
)
parts.append("</svg>")
(OUT / "thor_attack_overview.svg").write_text("\n".join(parts))
print("Custom overview written:", OUT / "thor_attack_overview.svg")

# MITRE's official, unmodified Python exporter, using the same pinned local catalog.
from mitreattack.navlayers import Layer, ToSvg, SVGConfig

official = dict(layers["combined"])
official["name"] = f"THOR v11 - Enterprise ATT&CK v{version}"
official["description"] = (
    f"Built-in YARA + Sigma. {len(sets['combined'])} explicitly tagged active technique/sub-technique IDs. Signature-tag associations; detection effectiveness not validated. Signature version {revision}."
)
original_annotations = {t["techniqueID"]: t for t in official["techniques"]}
# Explicit tactic rows preserve Navigator's "all official tactics" semantics.
# They also let the official exporter expand every parent, including untagged ones.
official["techniques"] = []
for tid, obj in sorted(catalog.techniques["enterprise-attack"].items()):
    if not a.active(obj):
        continue
    for phase in obj.get("kill_chain_phases", []):
        if phase["kill_chain_name"] != "mitre-attack":
            continue
        annotation = dict(
            original_annotations.get(tid, {"techniqueID": tid, "enabled": True})
        )
        annotation["tactic"] = phase["phase_name"]
        if "." not in tid:
            annotation["showSubtechniques"] = True
        official["techniques"].append(annotation)
(ROOT / ".local/renderer-input-detailed.json").write_text(
    json.dumps(official, indent=2) + "\n"
)
layer = Layer()
layer.from_dict(official)
config = SVGConfig(
    width=45,
    height=65,
    headerHeight=2.5,
    unit="in",
    showSubtechniques="all",
    fontSize=15,
    showFilters=False,
    showAbout=True,
    showDomain=True,
)
exporter = ToSvg(
    domain="enterprise",
    source="local",
    resource=str(args.attack_dir / f"enterprise-attack-{version}.json"),
    config=config,
)
exporter.to_svg(layerInit=layer, filepath=str(OUT / "THOR_APT_Scanner-detailed.svg"))
family_layer = dict(official)
family_layer["name"] = f"THOR v11 - technique-family view (ATT&CK v{version})"
family_layer["description"] = (
    f"{len(families)} associated technique families. Dark blue: direct parent tag. Light blue: tagged sub-technique only. A child association does not imply full parent coverage. Built-in YARA + Sigma; signature version {revision}."
)
family_layer["legendItems"] = [
    {"label": "Direct parent tag", "color": "#2563eb"},
    {"label": "Tagged sub-technique only", "color": "#93c5fd"},
]
family_layer["techniques"] = []
for annotation in official["techniques"]:
    tid = annotation["techniqueID"]
    if "." in tid:
        continue
    entry = dict(annotation)
    entry["showSubtechniques"] = False
    if tid in families and tid not in sets["combined"]:
        entry["color"] = "#93c5fd"
    family_layer["techniques"].append(entry)
family = Layer()
family.from_dict(family_layer)
family_exporter = ToSvg(
    domain="enterprise",
    source="local",
    resource=str(args.attack_dir / f"enterprise-attack-{version}.json"),
    config=SVGConfig(
        width=45,
        height=26,
        headerHeight=2.5,
        unit="in",
        showSubtechniques="none",
        fontSize=18,
        showFilters=False,
    ),
)
family_exporter.to_svg(layerInit=family, filepath=str(OUT / "THOR_APT_Scanner.svg"))
(ROOT / ".local/renderer-input-families.json").write_text(
    json.dumps(family_layer, indent=2) + "\n"
)
(ROOT / "data/renderer-provenance.json").write_text(
    json.dumps(
        {
            "official_renderer": "mitreattack-python",
            "official_renderer_version": importlib.metadata.version(
                "mitreattack-python"
            ),
            "custom_renderer": "Local SVG generator",
            "source_layer": "THOR_APT_Scanner.json",
            "stix_collection": "Enterprise " + version,
            "configuration": {
                "all_subtechniques": True,
                "width_inches": 45,
                "height_inches": 65,
            },
        },
        indent=2,
    )
    + "\n"
)
print("MITRE export written:", OUT / "THOR_APT_Scanner-detailed.svg")

if args.png:
    for stem, png_stem, width in [
        ("thor_attack_overview", "thor_attack_overview", 2100),
        ("THOR_APT_Scanner", "thor_coverage", 4320),
        ("THOR_APT_Scanner-detailed", "THOR_APT_Scanner-detailed", 4320),
    ]:
        subprocess.run(
            [
                "rsvg-convert",
                "-b",
                "white",
                "-w",
                str(width),
                "-o",
                str(OUT / (png_stem + ".png")),
                str(OUT / (stem + ".svg")),
            ],
            check=True,
        )

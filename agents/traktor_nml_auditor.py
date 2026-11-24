#!/usr/bin/env python3
"""
Standalone Traktor .nml History & Playlist Reconstructor (Zero Dependencies)
============================================================================
Parses Native Instruments Traktor `.nml` XML files, reconstructs chronological
deck transitions, and outputs an auditable JSON/CSV tracklist manifest.
"""
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def parse_traktor_nml(nml_path: Path) -> list[dict[str, str | float]]:
    tree = ET.parse(nml_path)
    root = tree.getroot()

    collection: dict[str, dict[str, str | float]] = {}
    for entry in root.findall(".//COLLECTION/ENTRY"):
        loc = entry.find("LOCATION")
        info = entry.find("INFO")
        tempo = entry.find("TEMPO")
        if loc is None:
            continue
        key = f"{loc.attrib.get('VOLUME', '')}{loc.attrib.get('DIR', '')}{loc.attrib.get('FILE', '')}"
        collection[key] = {
            "artist": entry.attrib.get("ARTIST", "Unknown"),
            "title": entry.attrib.get("TITLE", loc.attrib.get("FILE", "Untitled")),
            "bpm": round(float(tempo.attrib["BPM"]), 2) if tempo is not None and "BPM" in tempo.attrib else 0.0,
            "genre": info.attrib.get("GENRE", "") if info is not None else "",
            "duration_sec": int(info.attrib.get("PLAYTIME", 0)) if info is not None else 0,
        }

    tracks: list[dict[str, str | float]] = []
    for idx, item in enumerate(root.findall(".//PLAYLISTS//ENTRY/PRIMARYKEY"), start=1):
        key = item.attrib.get("KEY", "")
        meta = collection.get(key, {"artist": "Unknown", "title": key, "bpm": 0.0, "genre": "", "duration_sec": 0})
        tracks.append({"index": idx, "key": key, **meta})
    return tracks


def main() -> None:
    ap = argparse.ArgumentParser(description="Reconstruct tracklist manifest from Traktor .nml XML")
    ap.add_argument("nml_file", type=Path, help="Path to Traktor .nml playlist or history file")
    ap.add_argument("--out-json", type=Path, help="Optional output JSON path")
    ap.add_argument("--out-csv", type=Path, help="Optional output CSV path")
    args = ap.parse_args()

    tracks = parse_traktor_nml(args.nml_file)
    print(f"Parsed {len(tracks)} ordered tracks from {args.nml_file.name}")
    if args.out_json:
        args.out_json.write_text(json.dumps(tracks, indent=2), encoding="utf-8")
    if args.out_csv and tracks:
        with open(args.out_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(tracks[0].keys()))
            writer.writeheader()
            writer.writerows(tracks)


if __name__ == "__main__":
    main()
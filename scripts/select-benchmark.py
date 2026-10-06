"""Builds a benchmark manifest, the jars the false positive benchmark scans,
from Modrinth and CurseForge.

The benchmark has two tiers. The gate tier, benchmark/manifest.json, is small
enough to scan with every test run. The extended tier,
benchmark/extended/manifest.json, is far larger, runs before a rule change
ships, and leaves out every jar the gate already has.

Each tier draws groups from each platform:

- latest: the most downloaded mods, at their newest release
- one group per Minecraft version: the most downloaded mods for that
  version, at their newest release for it
- oldest: the most downloaded mods at their oldest release, which servers
  still run and where older networking code lives
- mid-tail: mods drawn at random from further down the download ranking,
  where code gets less review, with a fixed seed so the same rankings give
  the same draw

Each entry records its group. The same jar found twice is kept once, under
the first group that found it. Each rebuild can bring new findings that need
labels in benchmark/labels.json.

Usage: python scripts/select-benchmark.py gate|extended

Uses only the Python standard library. CurseForge needs an API key, read from
the MCSEC_CURSEFORGE_KEY environment variable or from
~/.mcsec/curseforge-key.txt. Without one, only Modrinth is selected.
"""

import importlib
import json
import random
import re
import sys
import time
import urllib.error
import urllib.parse
from pathlib import Path

# Reuses the fetch script's helpers without leaving a __pycache__ in scripts.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
fetch = importlib.import_module("fetch-corpus")

ROOT = Path(__file__).resolve().parent.parent
MINECRAFT_GAME_ID = 432
MODS_CLASS_ID = 6
SORT_BY_TOTAL_DOWNLOADS = 6
RELEASE_FILE_TYPE = 1
SHA1_ALGORITHM = 1
CURSEFORGE_PAGE = 50
# CurseForge pages no further than this many results into a listing.
CURSEFORGE_MAX_INDEX = 10000
MODRINTH_PAGE = 100
MAX_ATTEMPTS = 6

TIERS = {
    "gate": {
        "manifest": ROOT / "benchmark" / "manifest.json",
        # (group, Minecraft version or None for any, count per platform)
        "ranked": [("latest", None, 150), ("1.12.2", "1.12.2", 60), ("1.7.10", "1.7.10", 30)],
        "oldest": 0,
        "mid_tail": 60,
        "mid_tail_ranks": range(500, 5000),
        "seed": 2026,
        "description": (
            "The gate tier of the false positive benchmark, scanned with every test run. Drawn from Modrinth and "
            "CurseForge in four groups: the most downloaded mods at their newest release, the most downloaded for "
            "Minecraft 1.12.2 and for 1.7.10, and a seeded random draw from further down the rankings."
        ),
    },
    "extended": {
        "manifest": ROOT / "benchmark" / "extended" / "manifest.json",
        "ranked": [
            ("latest", None, 500),
            ("1.7.10", "1.7.10", 150),
            ("1.12.2", "1.12.2", 150),
            ("1.16.5", "1.16.5", 150),
            ("1.18.2", "1.18.2", 150),
            ("1.20.1", "1.20.1", 150),
        ],
        "oldest": 100,
        "mid_tail": 500,
        "mid_tail_ranks": range(150, 9900),
        "seed": 2027,
        "description": (
            "The extended tier of the false positive benchmark, scanned before a rule change ships. Drawn from "
            "Modrinth and CurseForge: the most downloaded mods at their newest release, the most downloaded for "
            "Minecraft 1.7.10, 1.12.2, 1.16.5, 1.18.2, and 1.20.1, the most downloaded at their oldest release, and a "
            "seeded random draw from further down the rankings. Leaves out every jar in the gate tier."
        ),
    },
}
USAGE = (
    "Each tier is downloaded into a cache beside its manifest by scripts/fetch-corpus.py <manifest>. Every finding "
    "on these jars is labeled in benchmark/labels.json."
)


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9._+-]+", "-", text).strip("-")


def get_json(url, headers=None):
    """Fetches JSON, waiting and retrying when the API limits the rate or fails."""
    for attempt in range(MAX_ATTEMPTS):
        try:
            return json.loads(fetch.get(url, headers))
        except urllib.error.HTTPError as error:
            if error.code != 429 and error.code < 500 or attempt == MAX_ATTEMPTS - 1:
                raise
        except urllib.error.URLError:
            if attempt == MAX_ATTEMPTS - 1:
                raise
        time.sleep(2**attempt)


def modrinth_search(offset, limit, game_version):
    facets = [["project_type:mod"]]
    if game_version:
        facets.append([f"versions:{game_version}"])
    query = urllib.parse.urlencode(
        {"index": "downloads", "offset": offset, "limit": limit, "facets": json.dumps(facets)}
    )
    return get_json(f"https://api.modrinth.com/v2/search?{query}")["hits"]


def modrinth_entry(hit, group, game_version, oldest=False):
    query = {"include_changelog": "false"}
    if game_version:
        query["game_versions"] = json.dumps([game_version])
    versions = get_json(
        f"https://api.modrinth.com/v2/project/{hit['project_id']}/version?{urllib.parse.urlencode(query)}"
    )
    with_jars = [v for v in versions if any(f["filename"].endswith(".jar") for f in v["files"])]
    releases = [v for v in with_jars if v["version_type"] == "release"] or with_jars
    if not releases:
        print(f"skipped {hit['title']}: no jar for {game_version or 'any version'}")
        return None
    pick = min if oldest else max
    chosen = pick(releases, key=lambda v: v["date_published"])
    jars = [f for f in chosen["files"] if f["filename"].endswith(".jar")]
    jar = next((f for f in jars if f["primary"]), jars[0])
    return {
        "name": f"{hit['title']} {chosen['version_number']}",
        "group": group,
        "downloads": hit["downloads"],
        "file": f"modrinth-{chosen['id']}-{safe_name(jar['filename'])}",
        "sha1": jar["hashes"]["sha1"],
        "source": {"modrinth": {"versionId": chosen["id"], "filename": jar["filename"]}},
    }


def modrinth(tier, rng):
    entries = []
    for group, game_version, count in tier["ranked"]:
        hits = []
        for offset in range(0, count, MODRINTH_PAGE):
            hits += modrinth_search(offset, min(MODRINTH_PAGE, count - offset), game_version)
        entries += [modrinth_entry(hit, group, game_version) for hit in hits]
        print(f"modrinth {group}: {len(hits)} mods")
    if tier["oldest"]:
        hits = []
        for offset in range(0, tier["oldest"], MODRINTH_PAGE):
            hits += modrinth_search(offset, min(MODRINTH_PAGE, tier["oldest"] - offset), None)
        entries += [modrinth_entry(hit, "oldest", None, oldest=True) for hit in hits]
        print(f"modrinth oldest: {len(hits)} mods")
    for rank in sorted(rng.sample(tier["mid_tail_ranks"], tier["mid_tail"])):
        entries += [modrinth_entry(hit, "mid-tail", None) for hit in modrinth_search(rank, 1, None)]
    print(f"modrinth mid-tail: {tier['mid_tail']} drawn")
    return [entry for entry in entries if entry]


def curseforge_search(headers, index, page_size, game_version):
    query = {
        "gameId": MINECRAFT_GAME_ID,
        "classId": MODS_CLASS_ID,
        "sortField": SORT_BY_TOTAL_DOWNLOADS,
        "sortOrder": "desc",
        "pageSize": page_size,
        "index": index,
    }
    if game_version:
        query["gameVersion"] = game_version
    url = f"https://api.curseforge.com/v1/mods/search?{urllib.parse.urlencode(query)}"
    return get_json(url, headers)["data"]


def curseforge_file_entry(mod, file, group):
    sha1 = next(h["value"] for h in file["hashes"] if h["algo"] == SHA1_ALGORITHM)
    return {
        "name": f"{mod['name']} {file['displayName']}",
        "group": group,
        "downloads": int(mod["downloadCount"]),
        "file": f"curseforge-{file['id']}-{safe_name(file['fileName'])}",
        "sha1": sha1,
        "source": {"curseforge": {"modId": mod["id"], "fileId": file["id"]}},
    }


def curseforge_allowed(mod):
    if mod.get("allowModDistribution") is False:
        print(f"skipped {mod['name']}: the author does not allow API downloads")
        return False
    return True


def curseforge_entry(headers, mod, group, game_version):
    if not curseforge_allowed(mod):
        return None
    indexes = [
        i
        for i in mod["latestFilesIndexes"]
        if i["filename"].endswith(".jar") and (game_version is None or i["gameVersion"] == game_version)
    ]
    releases = [i for i in indexes if i["releaseType"] == RELEASE_FILE_TYPE] or indexes
    if not releases:
        print(f"skipped {mod['name']}: no jar for {game_version or 'any version'}")
        return None
    # File IDs grow over time, so the largest is the newest upload.
    file_id = max(i["fileId"] for i in releases)
    file = get_json(f"https://api.curseforge.com/v1/mods/{mod['id']}/files/{file_id}", headers)["data"]
    if not file.get("isAvailable", True):
        print(f"skipped {mod['name']}: file {file_id} is not available")
        return None
    return curseforge_file_entry(mod, file, group)


def curseforge_oldest_entry(headers, mod):
    if not curseforge_allowed(mod):
        return None
    base = f"https://api.curseforge.com/v1/mods/{mod['id']}/files"
    total = get_json(f"{base}?index=0&pageSize=1", headers)["pagination"]["totalCount"]
    index = max(0, min(total, CURSEFORGE_MAX_INDEX) - CURSEFORGE_PAGE)
    files = get_json(f"{base}?index={index}&pageSize={CURSEFORGE_PAGE}", headers)["data"]
    jars = [f for f in files if f["fileName"].endswith(".jar") and f.get("isAvailable", True)]
    releases = [f for f in jars if f["releaseType"] == RELEASE_FILE_TYPE] or jars
    if not releases:
        print(f"skipped {mod['name']}: no jar among its oldest files")
        return None
    return curseforge_file_entry(mod, min(releases, key=lambda f: f["id"]), "oldest")


def curseforge(tier, key, rng):
    headers = {"x-api-key": key, "Accept": "application/json"}
    entries = []
    for group, game_version, count in tier["ranked"]:
        mods = []
        for index in range(0, count, CURSEFORGE_PAGE):
            mods += curseforge_search(headers, index, min(CURSEFORGE_PAGE, count - index), game_version)
        entries += [curseforge_entry(headers, mod, group, game_version) for mod in mods]
        print(f"curseforge {group}: {len(mods)} mods")
    if tier["oldest"]:
        mods = []
        for index in range(0, tier["oldest"], CURSEFORGE_PAGE):
            mods += curseforge_search(headers, index, min(CURSEFORGE_PAGE, tier["oldest"] - index), None)
        entries += [curseforge_oldest_entry(headers, mod) for mod in mods]
        print(f"curseforge oldest: {len(mods)} mods")
    for rank in sorted(rng.sample(tier["mid_tail_ranks"], tier["mid_tail"])):
        entries += [
            curseforge_entry(headers, mod, "mid-tail", None) for mod in curseforge_search(headers, rank, 1, None)
        ]
    print(f"curseforge mid-tail: {tier['mid_tail']} drawn")
    return [entry for entry in entries if entry]


def main():
    # Mod names can hold characters the Windows console encoding lacks.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) != 2 or sys.argv[1] not in TIERS:
        print(f"usage: {sys.argv[0]} {'|'.join(TIERS)}")
        return 2
    name = sys.argv[1]
    tier = TIERS[name]

    entries = modrinth(tier, random.Random(tier["seed"]))
    key = fetch.curseforge_key()
    if key:
        entries += curseforge(tier, key, random.Random(tier["seed"]))
    else:
        print("no CurseForge API key, selecting from Modrinth only")

    seen = set()
    if name != "gate":
        gate = json.loads(TIERS["gate"]["manifest"].read_text(encoding="utf-8"))["entries"]
        seen.update(entry["sha1"] for entry in gate)
    unique = []
    for entry in entries:
        if entry["sha1"] not in seen:
            seen.add(entry["sha1"])
            unique.append(entry)

    manifest_path = tier["manifest"]
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {"description": f"{tier['description']} {USAGE}", "entries": unique}
    manifest_path.write_text(json.dumps(manifest, indent="\t", ensure_ascii=False) + "\n", encoding="utf-8")
    groups = {}
    for entry in unique:
        groups[entry["group"]] = groups.get(entry["group"], 0) + 1
    summary = ", ".join(f"{count} {group}" for group, count in groups.items())
    print(f"{len(unique)} jars selected ({summary}), {len(entries) - len(unique)} duplicates dropped")
    return 0


if __name__ == "__main__":
    sys.exit(main())

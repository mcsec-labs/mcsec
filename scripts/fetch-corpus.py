"""Downloads the ground truth jars listed in corpus/manifest.json into
corpus/cache and checks each one's SHA-1.

Uses only the Python standard library. CurseForge entries need an API key,
read from the MCSEC_CURSEFORGE_KEY environment variable or from
~/.mcsec/curseforge-key.txt. Without one, those entries are skipped.

The jars include vulnerable mods. They are only ever parsed by the scanner,
never run.
"""

import hashlib
import json
import os
import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "corpus" / "manifest.json"
CACHE = ROOT / "corpus" / "cache"
USER_AGENT = "mcsec-labs/mcsec corpus fetch"


def curseforge_key():
    key = os.environ.get("MCSEC_CURSEFORGE_KEY")
    if key:
        return key.strip()
    path = Path.home() / ".mcsec" / "curseforge-key.txt"
    return path.read_text(encoding="utf-8").strip() if path.exists() else None


def get(url, headers=None):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def download_url(source, key):
    if "curseforge" in source:
        if not key:
            return None
        cf = source["curseforge"]
        body = get(
            f"https://api.curseforge.com/v1/mods/{cf['modId']}/files/{cf['fileId']}/download-url",
            {"x-api-key": key, "Accept": "application/json"},
        )
        return json.loads(body)["data"].replace(" ", "%20")
    if "modrinth" in source:
        mr = source["modrinth"]
        version = json.loads(get(f"https://api.modrinth.com/v2/version/{mr['versionId']}"))
        return next(f["url"] for f in version["files"] if f["filename"] == mr["filename"])
    if "github" in source:
        gh = source["github"]
        tag = urllib.parse.quote(gh["tag"], safe="")
        asset = urllib.parse.quote(gh["asset"], safe="")
        return f"https://github.com/{gh['repo']}/releases/download/{tag}/{asset}"
    raise ValueError(f"unknown source {source}")


def main():
    entries = json.loads(MANIFEST.read_text(encoding="utf-8"))["entries"]
    CACHE.mkdir(parents=True, exist_ok=True)
    key = curseforge_key()
    fetched = present = skipped = 0
    failed = []

    for entry in entries:
        path = CACHE / entry["file"]
        if path.exists() and hashlib.sha1(path.read_bytes()).hexdigest() == entry["sha1"]:
            present += 1
            continue
        try:
            url = download_url(entry["source"], key)
            if url is None:
                print(f"skipped {entry['name']}: no CurseForge API key")
                skipped += 1
                continue
            data = get(url)
            actual = hashlib.sha1(data).hexdigest()
            if actual != entry["sha1"]:
                raise ValueError(f"SHA-1 {actual} does not match the manifest's {entry['sha1']}")
            partial = path.with_suffix(path.suffix + ".part")
            partial.write_bytes(data)
            partial.replace(path)
            print(f"fetched {entry['name']}")
            fetched += 1
        except Exception as error:
            print(f"FAILED {entry['name']}: {error}")
            failed.append(entry["name"])

    print(f"{fetched} fetched, {present} already present, {skipped} skipped, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

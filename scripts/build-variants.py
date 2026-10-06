"""Compiles the variant corpus under corpus/variants with javac, once per
Java release, into corpus/variants/build/<release>.

The same source compiles to different bytecode on different releases, so
each release is a separate test of how well rules generalize. A source file
whose first line is "// REQUIRES java N" is skipped for releases below N.

Needs a JDK new enough for every release in RELEASES, with javac on PATH.
Uses only the Python standard library.
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VARIANTS = ROOT / "corpus" / "variants"
BUILD = VARIANTS / "build"
RELEASES = [8, 17, 21]
REQUIRES = re.compile(r"^//\s*REQUIRES java (\d+)")


def required_release(source):
    first_line = source.read_text(encoding="utf-8").splitlines()[0]
    match = REQUIRES.match(first_line)
    return int(match.group(1)) if match else 0


def main():
    if shutil.which("javac") is None:
        print("javac not found on PATH")
        return 1
    sources = sorted(path for path in VARIANTS.rglob("*.java") if BUILD not in path.parents)
    shutil.rmtree(BUILD, ignore_errors=True)

    for release in RELEASES:
        selected = [str(path) for path in sources if required_release(path) <= release]
        output = BUILD / str(release)
        output.mkdir(parents=True)
        result = subprocess.run(
            ["javac", "--release", str(release), "-nowarn", "-d", str(output), *selected],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(result.stdout + result.stderr)
            print(f"javac failed for release {release}")
            return 1
        classes = len(list(output.rglob("*.class")))
        print(f"release {release}: {len(selected)} sources, {classes} classes")
    return 0


if __name__ == "__main__":
    sys.exit(main())

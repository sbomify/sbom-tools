#!/usr/bin/env python3
"""Verify every pinned download still hashes to what bundles.toml claims.

This exists because of what Dependabot does. Bumping a version in go.mod,
bun.lock or global.json changes the URL -- the templates follow it -- but not
the digest beside it, and a stale digest is not a quiet inconvenience: the
download is refused and the bundle cannot be built.

Better for that to fail here, in a check that says exactly which digest needs
refreshing, than in the middle of a release. Run with --update to rewrite them.

    python scripts/check_digests.py [--update] [--component go]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from assemble_bundle import PLATFORMS, resolve_version  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "bundles.toml"
# php.net ships no binaries, so the php bundle pins a source tarball instead of
# a release asset and keeps it in its own file. It is the same kind of pin with
# the same failure -- a bumped version beside a stale digest refuses to
# download -- so it is checked here rather than left to surface halfway through
# a build. One pin, not four: the tarball is the same source on every
# platform, and both build jobs compile it.
PHP_RELEASE = ROOT / "php-release.json"
PHP_URL = "https://www.php.net/distributions/php-{version}.tar.gz"
CHUNK = 1 << 20


def digest_of(url: str, algorithm: str) -> str | None:
    hasher = hashlib.new(algorithm)
    try:
        with urllib.request.urlopen(url, timeout=600) as response:  # noqa: S310
            while chunk := response.read(CHUNK):
                hasher.update(chunk)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        print(f"    download failed: {exc}", file=sys.stderr)
        return None
    return hasher.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update", action="store_true", help="rewrite digests that no longer match")
    parser.add_argument("--component", help="only this component")
    args = parser.parse_args()

    # Each pin remembers the file it came from, because --update rewrites that
    # file and the two are different formats.
    sources = {MANIFEST: MANIFEST.read_text()}
    bundles = tomllib.loads(sources[MANIFEST])["bundle"]

    # Keyed on the URL, so each distinct artifact is downloaded once however
    # many entries point at it. Two things make that worth doing: a component
    # can appear in several bundles (bun is in four of them), and the
    # platform-independent components name the same archive under all four
    # platforms (Maven, Gradle, sbt and composer.phar are JVM applications or
    # bytecode). Checking per entry instead meant fetching Gradle's 130MB four
    # times to compare it against the same digest four times.
    #
    # Platforms sharing a URL must agree about its digest, and disagreeing is
    # worth a failure rather than a silent preference for whichever came first:
    # it means one of four otherwise identical entries has been mistyped, and
    # that entry is the one that would refuse to download during a release.
    pins: dict[tuple[str, str], tuple[str, str, Path, list[str]]] = {}
    for bundle in bundles.values():
        for name, spec in (bundle.get("upstream") or {}).items():
            if args.component and args.component != name:
                continue
            version = resolve_version(spec)
            for platform in PLATFORMS:
                per_platform = spec.get(platform)
                if not per_platform:
                    continue
                algorithm = next((a for a in ("sha256", "sha512") if a in per_platform), "")
                if not algorithm:
                    continue
                url = str(per_platform["url"]).replace("{version}", version)
                digest = str(per_platform[algorithm])
                if existing := pins.get((name, url)):
                    if (existing[0], existing[1]) != (algorithm, digest):
                        print(
                            f"error: {name} pins {url} as {algorithm}:{digest[:16]}… for "
                            f"{platform} but {existing[0]}:{existing[1][:16]}… for "
                            f"{', '.join(existing[3])}",
                            file=sys.stderr,
                        )
                        return 1
                    # A component in four bundles reaches the same URL four
                    # times for the same platform; record which platforms want
                    # it, not how many bundles asked.
                    if platform not in existing[3]:
                        existing[3].append(platform)
                    continue
                pins[(name, url)] = (algorithm, digest, MANIFEST, [platform])

    if PHP_RELEASE.exists() and args.component in (None, "php"):
        sources[PHP_RELEASE] = PHP_RELEASE.read_text()
        php = json.loads(sources[PHP_RELEASE])["php"]
        url = PHP_URL.format(version=php["version"])
        pins[("php", url)] = ("sha256", str(php["sha256"]), PHP_RELEASE, ["source"])

    stale = []
    for (name, url), (algorithm, expected, source, platforms) in sorted(pins.items()):
        # "all" rather than four names that add nothing: a component published
        # once for every platform is the uninteresting case, and spelling it
        # out is what would make the interesting case -- a pin missing from one
        # platform -- hard to see in the column.
        where = "all" if len(platforms) == len(PLATFORMS) else ", ".join(platforms)
        actual = digest_of(url, algorithm)
        if actual is None:
            stale.append((name, where, url, algorithm, expected, "unreachable"))
            print(f"  {name:<10}{where:<15}UNREACHABLE  {url}")
            continue
        if actual == expected:
            print(f"  {name:<10}{where:<15}ok")
            continue
        stale.append((name, where, url, algorithm, expected, actual))
        print(f"  {name:<10}{where:<15}STALE   pinned {expected[:16]}… actual {actual[:16]}…")
        if args.update:
            sources[source] = sources[source].replace(expected, actual)

    if args.update and stale:
        rewritten = [entry for entry in stale if entry[5] != "unreachable"]
        touched = []
        for path, updated in sources.items():
            if updated != path.read_text():
                path.write_text(updated)
                touched.append(path.name)
        print(f"\nrewrote {len(rewritten)} digest(s) in {', '.join(sorted(touched))}")
        return 0

    if stale:
        print(f"\n{len(stale)} pin(s) need attention. Run with --update to refresh them.", file=sys.stderr)
        return 1
    print(f"\nall {len(pins)} pins match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

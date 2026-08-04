#!/usr/bin/env python3
"""Assemble one relocatable ecosystem bundle.

A bundle is a single archive holding everything an ecosystem needs: the tools
compiled from the lockfiles here, plus the self-hosting toolchain they shell
out to, pinned by the vendor's published digest.

It unpacks into any writable directory and runs from there. Nothing is
installed system-wide and no path inside is absolute, so a bundle works for a
uid with no home directory and no privileges -- which is the point. The
alternative the action used to have was `apt-get install` at run time, which
forces the container to run as root and pins nothing.

The archive describes itself in bundle.toml, so a consumer unpacks it, reads
what to put on PATH and which environment to set, and needs no prior knowledge
of the bundle's shape. Adding an ecosystem therefore changes nothing on the
consumer side.

Usage:
    assemble_bundle.py --bundle rust --arch amd64 --built-dir dist --out out
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHUNK = 1 << 20


def die(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def download_verified(url: str, algorithm: str, digest: str, dest: Path) -> None:
    """Fetch url, refusing it unless it hashes to the pinned digest."""
    print(f"  fetching {url.rsplit('/', 1)[-1]}")
    hasher = hashlib.new(algorithm)
    with urllib.request.urlopen(url, timeout=300) as response, dest.open("wb") as handle:  # noqa: S310
        while chunk := response.read(CHUNK):
            hasher.update(chunk)
            handle.write(chunk)
    actual = hasher.hexdigest()
    if actual != digest:
        die(f"{url}: expected {algorithm}:{digest}, got {actual}")
    print(f"  ✓ {algorithm} matches the pin ({actual[:16]}…)")


def safe_extract(archive: Path, into: Path) -> None:
    """Unpack an archive, refusing any member that escapes the destination."""
    into.mkdir(parents=True, exist_ok=True)
    if archive.suffix == ".zip":
        # Gradle ships a zip. zipfile drops the executable bit, so bin/gradle
        # comes out unrunnable unless the mode is restored from the entry.
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                target = (into / info.filename).resolve()
                if not str(target).startswith(str(into.resolve())):
                    die(f"{archive.name}: unsafe entry {info.filename!r}")
            zf.extractall(into)  # noqa: S202 - every member checked above
            for info in zf.infolist():
                mode = info.external_attr >> 16
                if mode:
                    (into / info.filename).chmod(mode & 0o777)
        return
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            target = (into / member.name).resolve()
            if not str(target).startswith(str(into.resolve())):
                die(f"{archive.name}: unsafe entry {member.name!r}")
            if member.issym() or member.islnk():
                link = (into / member.name).parent / member.linkname
                if not str(link.resolve()).startswith(str(into.resolve())):
                    die(f"{archive.name}: link escapes the bundle: {member.name!r}")
        tar.extractall(into)  # noqa: S202 - every member checked above


def strip_container(directory: Path) -> None:
    """Collapse an archive that wraps everything in one top-level directory.

    go/, jdk-21.0.12+8/ and apache-maven-3.9.16/ all do this. Removing the
    wrapper is what makes the layout inside a bundle stable and version-free,
    so a consumer never has to know which version it unpacked.
    """
    entries = list(directory.iterdir())
    if len(entries) != 1 or not entries[0].is_dir():
        return
    wrapper = entries[0]
    holding = directory.parent / (directory.name + ".unwrap")
    wrapper.rename(holding)
    directory.rmdir()
    holding.rename(directory)


def add_upstream(name: str, spec: dict, arch: str, prefix: Path, scratch: Path) -> None:
    """Fetch one pinned upstream component into the bundle prefix."""
    per_arch = spec.get(arch)
    if not per_arch:
        die(f"{name}: no asset for {arch}")
    algorithm = next((a for a in ("sha256", "sha512") if a in per_arch), "")
    if not algorithm:
        die(f"{name}/{arch}: needs a sha256 or sha512")

    url = per_arch["url"]
    if spec.get("kind") == "raw":
        # A bare executable, e.g. cdxgen's single-file build.
        target = prefix / "bin" / spec.get("bin_name", name)
        target.parent.mkdir(parents=True, exist_ok=True)
        download_verified(url, algorithm, per_arch[algorithm], target)
        target.chmod(0o755)
        return

    archive = scratch / url.rsplit("/", 1)[-1]
    download_verified(url, algorithm, per_arch[algorithm], archive)
    staging = scratch / f"unpack-{name}"
    safe_extract(archive, staging)
    if spec.get("strip_container"):
        strip_container(staging)

    into = prefix / spec["into"] if spec.get("into") else prefix
    into.mkdir(parents=True, exist_ok=True)
    for entry in staging.iterdir():
        destination = into / entry.name
        if destination.exists():
            # Two components unpacking into one prefix (cargo and rustc) share
            # bin/ and lib/; merge rather than clobbering the first one.
            if destination.is_dir() and entry.is_dir():
                shutil.copytree(entry, destination, dirs_exist_ok=True, symlinks=True)
                continue
            die(f"{name}: {destination.name} already exists in the bundle")
        shutil.move(str(entry), str(destination))


def write_manifest(bundle: str, spec: dict, arch: str, prefix: Path, provides: list[str]) -> None:
    """Describe the bundle to whoever unpacks it."""
    # Every directory holding executables, not just the top one. A JDK
    # keeps java in jdk/bin and Maven keeps mvn in maven/bin, so a single
    # bin_subdir would advertise cdxgen and hide the two tools it shells
    # out to.
    bin_dirs = ["bin"] + sorted(
        f"{c['into']}/bin"
        for c in (spec.get("upstream") or {}).values()
        if c.get("into") and (prefix / c["into"] / "bin").is_dir()
    )
    lines = [
        "# Written by scripts/assemble_bundle.py. Read this rather than",
        "# assuming a layout: it is what lets a consumer support a new bundle",
        "# without being changed.",
        "[bundle]",
        f'name = "{bundle}"',
        f'arch = "{arch}"',
        f'description = "{spec.get("description", "")}"',
        f"provides = [{', '.join(repr(p) for p in sorted(provides))}]".replace("'", '"'),
        f"bin_dirs = [{', '.join(chr(34) + d + chr(34) for d in bin_dirs)}]",
    ]
    env = spec.get("env") or {}
    if env:
        lines.append("")
        lines.append("# {prefix} is substituted with wherever this was unpacked.")
        lines.append("[env]")
        lines.extend(f'{key} = "{value}"' for key, value in sorted(env.items()))
    (prefix / "bundle.toml").write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--arch", required=True, choices=("amd64", "arm64"))
    parser.add_argument("--built-dir", type=Path, default=ROOT / "dist")
    parser.add_argument("--out", type=Path, default=ROOT / "out")
    args = parser.parse_args()

    bundles = tomllib.loads((ROOT / "bundles.toml").read_text())["bundle"]
    if args.bundle not in bundles:
        die(f"unknown bundle {args.bundle!r}; known: {', '.join(sorted(bundles))}")
    spec = bundles[args.bundle]

    args.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp)
        prefix = scratch / "prefix"
        (prefix / "bin").mkdir(parents=True)
        provides: list[str] = []

        for tool in spec.get("built", []):
            source = args.built_dir / f"{tool}-linux-{args.arch}"
            if not source.is_file():
                die(f"{tool}: {source} is missing; build it before assembling")
            target = prefix / "bin" / tool
            shutil.copy2(source, target)
            target.chmod(0o755)
            provides.append(tool)
            print(f"  included {tool} (built here)")

        for name, upstream in (spec.get("upstream") or {}).items():
            add_upstream(name, upstream, args.arch, prefix, scratch)
            provides.append(name)

        write_manifest(args.bundle, spec, args.arch, prefix, provides)

        archive = args.out / f"{args.bundle}-linux-{args.arch}.tar.gz"
        # Sorted, with fixed ownership and timestamps: the same inputs should
        # produce the same bytes, or the digest we attest is noise.
        subprocess.run(  # noqa: S603
            [
                "tar", "--sort=name", "--owner=0", "--group=0", "--numeric-owner",
                "--mtime=@0", "--format=gnu", "-czf", str(archive), "-C", str(prefix), ".",
            ],
            check=True,
        )

    size = archive.stat().st_size / (1024 * 1024)
    print(f"  {archive.name}: {size:.1f} MB, provides {', '.join(sorted(provides))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

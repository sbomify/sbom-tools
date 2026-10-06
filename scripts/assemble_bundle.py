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
    assemble_bundle.py --bundle rust --os linux --arch amd64 --built-dir dist
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import tomllib
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CHUNK = 1 << 20

#: Every platform a bundle is published for, as "<os>-<arch>".
#:
#: The operating system is a real dimension rather than a detail of the
#: architecture: a vendor ships a different artifact for each, the digest
#: beside it is what makes the download safe, and the two systems disagree
#: about what "self-contained" even means -- Linux bundles carry statically
#: linked binaries, while macOS has no static libSystem and settles for
#: binaries that load nothing but the OS. bundles.toml is keyed on these
#: strings and so are the names of everything published.
OSES = ("linux", "darwin")
ARCHES = ("amd64", "arm64")
PLATFORMS = tuple(f"{os_}-{arch}" for os_ in OSES for arch in ARCHES)


def _version_from_go_toolchain(path: Path) -> str:
    """The toolchain directive in go.mod, not the go one.

    `go` is the minimum the module graph builds with; `toolchain` is what we
    actually build and ship.
    """
    text = path.read_text()
    for pattern in (r"^toolchain\s+go(\S+)", r"^go\s+(\S+)"):
        if match := re.search(pattern, text, re.M):
            return match.group(1)
    die(f"{path} has neither a toolchain nor a go directive")
    raise AssertionError  # unreachable; die exits


def _version_from_bun_lock(path: Path, package: str) -> str:
    """A package's resolved version in bun.lock.

    Matched rather than parsed: bun.lock is JSONC, which json rejects.
    """
    pattern = re.compile(rf'"{re.escape(package)}":\s*\[\s*"{re.escape(package)}@([^"]+)"')
    match = pattern.search(path.read_text())
    if not match:
        die(f"{package} not found in {path}")
    version = match.group(1)  # type: ignore[union-attr]
    if not re.fullmatch(r"\d[\w.+-]*", version):
        die(f"{package} in {path} resolves to {version!r}, which is not a released version")
    return version


def _version_from_global_json(path: Path) -> str:
    """The SDK version in global.json."""
    return str(json.loads(path.read_text())["sdk"]["version"])


#: Where a component's version comes from, when it comes from a manifest a bot
#: maintains rather than a literal here.
VERSION_READERS = {
    "go.mod": lambda p, _s: _version_from_go_toolchain(p),
    "bun.lock": lambda p, s: _version_from_bun_lock(p, str(s["package"])),
    "global.json": lambda p, _s: _version_from_global_json(p),
}


def resolve_version(spec: dict) -> str:
    """A component's version, from its manifest where one owns it.

    Restating a version here would put it out of Dependabot's reach, which is
    how a pin goes stale without anything failing: a tool that is still
    downloadable never complains about being old.
    """
    source = spec.get("version_from")
    if not source:
        return str(spec["version"])
    path = ROOT / str(source["file"])
    if not path.exists():
        die(f"{source['file']} not found (looked in {path})")
    reader = VERSION_READERS.get(path.name)
    if reader is None:
        die(f"no version reader for {path.name}")
    return reader(path, source)  # type: ignore[misc]


def component_setting(spec: dict, platform: str, key: str, default: Any = None) -> Any:
    """One of a component's settings, which a platform may override.

    Most are the same wherever the component is unpacked -- `into`, `kind`,
    `strip_container` -- and belong on the component. A few are facts about
    the vendor's archive rather than about the bundle, and vendors differ:
    Temurin wraps its macOS tree in Contents/Home, so that platform sets its
    own `payload` and the bundle still ends up with jdk/bin. Overriding beats
    a second component that is the same component.
    """
    per_platform = spec.get(platform) or {}
    if key in per_platform:
        return per_platform[key]
    return spec.get(key, default)


def die(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


#: Where verified downloads are kept between runs.
#:
#: Every bundle pulls its toolchain from the vendor -- a 190MB JDK, a .NET SDK
#: larger than that, Go, Rust, Gradle, Maven, sbt, bun -- and CI assembles one
#: archive per bundle and platform. Without this each job fetched all of it
#: again from the vendor's CDN on every build, for artifacts pinned to an exact
#: digest and therefore incapable of changing.
DOWNLOAD_CACHE = Path(
    os.environ.get("SBOM_TOOLS_DOWNLOAD_CACHE", Path.home() / ".cache" / "sbom-tools" / "downloads")
)


def _digest_of(path: Path, algorithm: str) -> str:
    hasher = hashlib.new(algorithm)
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            hasher.update(chunk)
    return hasher.hexdigest()


def download_verified(url: str, algorithm: str, digest: str, dest: Path) -> None:
    """Fetch url, refusing it unless it hashes to the pinned digest.

    Cached by digest rather than by URL, so the cache cannot serve the wrong
    bytes: an entry is only used when it already hashes to what the manifest
    demands. A version bump changes the digest and therefore misses, and a
    corrupted entry misses too rather than poisoning the build.
    """
    name = url.rsplit("/", 1)[-1]
    cached = DOWNLOAD_CACHE / f"{algorithm}-{digest}"
    if cached.is_file() and _digest_of(cached, algorithm) == digest:
        shutil.copy2(cached, dest)
        print(f"  ✓ {name} from cache ({algorithm} {digest[:16]}…)")
        return

    print(f"  fetching {name}")
    hasher = hashlib.new(algorithm)
    with urllib.request.urlopen(url, timeout=300) as response, dest.open("wb") as handle:  # noqa: S310
        while chunk := response.read(CHUNK):
            hasher.update(chunk)
            handle.write(chunk)
    actual = hasher.hexdigest()
    if actual != digest:
        die(f"{url}: expected {algorithm}:{digest}, got {actual}")
    print(f"  ✓ {algorithm} matches the pin ({actual[:16]}…)")
    try:
        DOWNLOAD_CACHE.mkdir(parents=True, exist_ok=True)
        # Written aside then renamed: two bundles assembling in parallel share
        # this directory, and a half-written entry that happened to be read
        # would fail its digest check but waste the fetch.
        staging = DOWNLOAD_CACHE / f".{algorithm}-{digest}.partial"
        shutil.copy2(dest, staging)
        staging.replace(cached)
    except OSError as exc:  # pragma: no cover - caching is an optimisation
        print(f"  note: could not cache {name}: {exc}")


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


def add_upstream(name: str, spec: dict, platform: str, prefix: Path, scratch: Path) -> None:
    """Fetch one pinned upstream component into the bundle prefix."""
    per_platform = spec.get(platform)
    if not per_platform:
        die(f"{name}: no asset for {platform}")
    algorithm = next((a for a in ("sha256", "sha512") if a in per_platform), "")
    if not algorithm:
        die(f"{name}/{platform}: needs a sha256 or sha512")

    def setting(key: str, default: Any = None) -> Any:
        return component_setting(spec, platform, key, default)

    # {version} in a URL follows the manifest the version came from, so a
    # Dependabot bump reaches the download instead of leaving it pointing at
    # the old release with a digest that no longer matches.
    url = str(per_platform["url"]).replace("{version}", resolve_version(spec))
    if setting("kind") == "raw":
        # A bare executable, e.g. cdxgen's single-file build.
        target = prefix / "bin" / setting("bin_name", name)
        target.parent.mkdir(parents=True, exist_ok=True)
        download_verified(url, algorithm, per_platform[algorithm], target)
        target.chmod(0o755)
        return

    archive = scratch / url.rsplit("/", 1)[-1]
    download_verified(url, algorithm, per_platform[algorithm], archive)
    staging = scratch / f"unpack-{name}"
    safe_extract(archive, staging)
    if setting("strip_container"):
        strip_container(staging)

    if keep := setting("keep"):
        # Some distributions are mostly things the bundle will never use --
        # Node ships 84MB of headers and npm alongside the interpreter. Keep
        # the named paths and drop the rest.
        wanted = {str(k) for k in keep}
        for entry in sorted(staging.rglob("*"), reverse=True):
            rel = str(entry.relative_to(staging))
            if any(rel == w or rel.startswith(w + "/") or w.startswith(rel + "/") for w in wanted):
                continue
            if entry.is_dir():
                shutil.rmtree(entry, ignore_errors=True)
            else:
                entry.unlink(missing_ok=True)

    if payload := setting("payload"):
        # A Rust dist tarball is an installer, not a tree to unpack: under the
        # version-named wrapper it carries the component itself (cargo/,
        # rustc/) alongside install.sh, components, git-commit-info and the
        # licences. Merging all of that put two components' identical
        # metadata files in each other's way, which is what "git-commit-info
        # already exists in the bundle" was. Take the component, leave the
        # installer.
        inner = staging / str(payload)
        if not inner.is_dir():
            die(f"{name}: expected payload directory {payload!r} in the archive")
        staging = inner

    into = prefix / setting("into") if setting("into") else prefix
    into.mkdir(parents=True, exist_ok=True)
    excluded = set(setting("exclude") or ())
    for entry in staging.iterdir():
        if entry.name in excluded:
            continue
        destination = into / entry.name
        if destination.exists():
            # Two components unpacking into one prefix (cargo and rustc) share
            # bin/ and lib/; merge rather than clobbering the first one.
            if destination.is_dir() and entry.is_dir():
                shutil.copytree(entry, destination, dirs_exist_ok=True, symlinks=True)
                continue
            die(f"{name}: {destination.name} already exists in the bundle")
        shutil.move(str(entry), str(destination))


def install_from_lockfile(prefix: Path, scratch: Path) -> None:
    """Install cdxgen from bun.lock, letting bun do the verifying.

    cdxgen is one of our tools, so it is pinned where the rest are -- in a
    lockfile, checked by the package manager that owns it. bun.lock records a
    sha512 for it and 197 other packages, and --frozen-lockfile refuses
    anything that does not match. Shipping upstream's prebuilt binary instead
    meant a second pin: our own sha256, of a different artefact, in a file no
    bot can read.

    --omit=optional drops 375MB of per-platform plugin binaries nothing here
    uses; verified identical output without them, 99 components for
    symfony/demo either way.
    """
    for name in ("package.json", "bun.lock"):
        shutil.copy(ROOT / name, prefix / name)
    # The bun already in the prefix, which the runtime step fetched and checked
    # against its pinned sha256 moments ago. Requiring one on the host instead
    # broke every cdxgen-bearing bundle the first time this ran in CI, where no
    # bun is installed -- and "install one in the build environment" would have
    # meant a second bun, from somewhere else, pinned by nothing, doing the
    # integrity check that is the entire point of installing from a lockfile.
    #
    # It reads bun.lock and verifies each package against the sha512 recorded
    # there. It is also what cdxgen runs under, so it ships either way.
    bundled = prefix / "bin" / "bun"
    bun = str(bundled) if bundled.is_file() else shutil.which("bun")
    if not bun:
        die("no bun in the prefix and none on PATH; the bun runtime must be added before this step")
    result = subprocess.run(  # noqa: S603
        [bun, "install", "--frozen-lockfile", "--production", "--omit=optional"],
        cwd=prefix, capture_output=True, text=True, timeout=1800,
    )
    if result.returncode != 0:
        die(f"bun install failed: {(result.stderr or result.stdout).strip()[:300]}")
    installed = prefix / "node_modules" / "@cyclonedx" / "cdxgen" / "bin" / "cdxgen.js"
    if not installed.is_file():
        die("bun install completed but cdxgen is not present")
    print(f"  cdxgen installed from bun.lock ({sum(1 for _ in (prefix / 'node_modules').iterdir())} packages)")


#: Build plugins the bundle's tools fetch at run time, and where their pinned
#: versions are read from.
#:
#: These are not installed into the bundle -- Maven, Gradle and sbt download
#: them themselves -- but the consumer has to name a version when it applies
#: them, and that version has to come from somewhere a bot watches. Recording
#: it in bundle.toml means the consumer reads it off the bundle it already
#: fetched instead of carrying its own copy of these manifests.
PLUGIN_PINS = {
    "cyclonedx-maven": ("tools/pom.xml", "cyclonedx-maven-plugin"),
    "sbt-sbom": ("tools/pom.xml", "sbt-sbom_2.12_1.0"),
    "cyclonedx-gradle": ("tools/build.gradle", "org.cyclonedx:cyclonedx-gradle-plugin"),
}


def _plugin_version(manifest: str, selector: str) -> str:
    """The pinned version of one build plugin, from the manifest that owns it."""
    text = (ROOT / manifest).read_text()
    if manifest.endswith(".xml"):
        # <artifactId>X</artifactId> ... <version>V</version>, in that order.
        match = re.search(
            rf"<artifactId>{re.escape(selector)}</artifactId>\s*<version>([^<]+)</version>",
            text,
        )
    else:
        match = re.search(rf'{re.escape(selector)}:([0-9][^"\'\s]*)', text)
    if not match:
        die(f"{selector} not found in {manifest}")
    return match.group(1).strip()  # type: ignore[union-attr]


def _executables(prefix: Path, bin_dirs: list[str]) -> set[str]:
    """Every command this bundle actually puts on PATH.

    `provides` names ecosystems rather than executables -- the JVM bundle
    provides "maven", and the thing you run is "mvn" -- so a wrapper's
    fallback has to be checked against what is really in bin_dirs.

    Files only. Directories carry the execute bit as a matter of course -- it
    is what makes them traversable -- so counting anything +x would let a
    subdirectory of bin/ pass as a command you could run. is_file() follows
    symlinks, which is right: a symlinked executable is still executable.
    """
    found: set[str] = set()
    for directory in bin_dirs:
        candidate = prefix / directory
        if not candidate.is_dir():
            continue
        found.update(entry.name for entry in candidate.iterdir() if entry.is_file() and os.access(entry, os.X_OK))
    return found


def write_manifest(bundle: str, spec: dict, platform: str, prefix: Path, provides: list[str]) -> None:
    """Describe the bundle to whoever unpacks it."""
    target_os, arch = platform.split("-", 1)
    # Every directory holding executables, not just the top one. A JDK
    # keeps java in jdk/bin and Maven keeps mvn in maven/bin, so a single
    # bin_subdir would advertise cdxgen and hide the two tools it shells
    # out to.
    extra: set[str] = set()
    for component in (spec.get("upstream") or {}).values():
        # An explicit bin_dir wins: the .NET SDK puts its executable at the
        # root of its payload rather than under bin/, so deriving "<into>/bin"
        # found nothing and dotnet never reached PATH.
        if declared := component_setting(component, platform, "bin_dir"):
            if (prefix / str(declared)).is_dir():
                extra.add(str(declared))
            continue
        into = component_setting(component, platform, "into")
        if into and (prefix / str(into) / "bin").is_dir():
            extra.add(f"{into}/bin")
    bin_dirs = ["bin"] + sorted(extra)
    lines = [
        "# Written by scripts/assemble_bundle.py. Read this rather than",
        "# assuming a layout: it is what lets a consumer support a new bundle",
        "# without being changed.",
        "[bundle]",
        f'name = "{bundle}"',
        # os and arch separately rather than one "platform" string, because a
        # consumer already knows which of the two it is checking against -- it
        # compares os to its own uname and arch to its own machine.
        f'os = "{target_os}"',
        f'arch = "{arch}"',
        f'description = "{spec.get("description", "")}"',
        f"provides = [{', '.join(repr(p) for p in sorted(provides))}]".replace("'", '"'),
        f"bin_dirs = [{', '.join(chr(34) + d + chr(34) for d in bin_dirs)}]",
    ]
    if spec.get("build_plugins"):
        lines.append("")
        lines.append("# Plugins the tools here fetch at run time. A consumer applies these")
        lines.append("# by coordinate and needs the version; reading it from the bundle")
        lines.append("# saves it from keeping its own copy of the manifests that pin them.")
        lines.append("[plugins]")
        for name in sorted(PLUGIN_PINS):
            manifest, selector = PLUGIN_PINS[name]
            lines.append(f'{name} = "{_plugin_version(manifest, selector)}"')

    wrappers = spec.get("wrappers") or {}
    if wrappers:
        lines.append("")
        lines.append("# Build-tool wrappers a project may commit, and what to run instead")
        lines.append("# when one cannot. `tool` is the executable here that stands in for")
        lines.append("# the wrapper; `needs`, where present, is a path relative to the")
        lines.append("# project that the wrapper cannot bootstrap without.")
        # Against the executables alone, never `provides`. `provides` names
        # ecosystems, so accepting it would wave through the exact mistake
        # this guard exists to catch: `tool = "maven"` is not runnable -- the
        # command is `mvn` -- yet "maven" is in `provides`.
        shipped = _executables(prefix, bin_dirs)
        for name in sorted(wrappers):
            declared = wrappers[name]
            # A wrapper table holds three keys and nothing else. Anything else
            # in there did not mean to be: TOML gives a bare key to whichever
            # table was opened last, so a `built =` or `env =` written after a
            # [bundle.X.wrappers.Y] header lands here rather than on the
            # bundle. That is not a hypothetical -- it is how the jvm bundle
            # spent two months shipping without syft, without cdxgen and
            # without JAVA_HOME, while assembling and attesting perfectly
            # well. Keys the bundle lost are keys this wrapper gained, so this
            # is where it is cheapest to notice.
            if stray := sorted(set(declared) - {"script", "tool", "needs"}):
                die(
                    f"wrapper {name!r} in bundle {bundle!r} declares {', '.join(stray)}, "
                    "which are not wrapper keys -- they were almost certainly meant for "
                    f"[bundle.{bundle}], and belong above the first sub-table under it"
                )
            for required in ("script", "tool"):
                if not declared.get(required):
                    die(f"wrapper {name!r} in bundle {bundle!r} declares no {required}")
            if declared["tool"] not in shipped:
                die(f"wrapper {name!r} falls back to {declared['tool']!r}, which this bundle does not ship")
            lines.append("")
            lines.append(f"[wrappers.{name}]")
            for key in ("script", "tool", "needs"):
                if value := declared.get(key):
                    lines.append(f'{key} = "{value}"')

    env = spec.get("env") or {}
    if env:
        lines.append("")
        lines.append("# {prefix} is substituted with wherever this was unpacked.")
        lines.append("[env]")
        lines.extend(f'{key} = "{value}"' for key, value in sorted(env.items()))
    (prefix / "bundle.toml").write_text("\n".join(lines) + "\n")


def gnu_tar() -> str:
    """A GNU tar, because the deterministic flags below are GNU tar's.

    macOS `tar` is bsdtar, and the deterministic flags are not portable to it:
    it has no --sort at all, and --mtime means "only files newer than this" to
    bsdtar rather than "stamp every member with this". Reproducibility would
    fail quietly -- member order following the filesystem, timestamps following
    the build -- which is the worst way for it to fail, since the digest we
    attest would simply be noise. The runner images ship GNU tar as `gtar`.
    """
    for candidate in ("tar", "gtar"):
        path = shutil.which(candidate)
        if not path:
            continue
        probe = subprocess.run([path, "--version"], capture_output=True, text=True, check=False)  # noqa: S603
        if "GNU tar" in probe.stdout:
            return path
    die("no GNU tar found (looked for tar and gtar); bsdtar cannot write a reproducible archive")
    raise AssertionError  # unreachable; die exits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True)
    # Required rather than defaulted to the host: the output file is named for
    # it, and a bundle quietly labelled linux because that is what the build
    # machine happened to be would be worse than no bundle.
    parser.add_argument("--os", dest="target_os", required=True, choices=OSES)
    parser.add_argument("--arch", required=True, choices=ARCHES)
    parser.add_argument("--built-dir", type=Path, default=ROOT / "dist")
    parser.add_argument("--out", type=Path, default=ROOT / "out")
    args = parser.parse_args()
    platform = f"{args.target_os}-{args.arch}"

    bundles = tomllib.loads((ROOT / "bundles.toml").read_text())["bundle"]
    if args.bundle not in bundles:
        die(f"unknown bundle {args.bundle!r}; known: {', '.join(sorted(bundles))}")
    spec = bundles[args.bundle]
    # Every bundle exists to deliver tools compiled from the lockfiles here;
    # the vendor toolchain beside them is what those tools shell out to. One
    # that declares none is not a bundle, and the way to end up with one is a
    # `built =` that a sub-table above it quietly captured.
    if not spec.get("built"):
        die(f"bundle {args.bundle!r} declares no built tools; see [bundle.{args.bundle}] in bundles.toml")

    args.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp)
        prefix = scratch / "prefix"
        (prefix / "bin").mkdir(parents=True)
        provides: list[str] = []

        # The launcher is built under its own name so it does not collide with
        # the package it runs, but it goes on PATH as cdxgen.
        installed_as = {"cdxgen-launcher": "cdxgen"}

        for tool in spec.get("built", []):
            source = args.built_dir / f"{tool}-{platform}"
            if not source.is_file():
                die(f"{tool}: {source} is missing; build it before assembling")
            name = installed_as.get(tool, tool)
            target = prefix / "bin" / name
            shutil.copy2(source, target)
            target.chmod(0o755)
            if name not in provides:
                provides.append(name)
            print(f"  included {name} (built here)")

        for name, upstream in (spec.get("upstream") or {}).items():
            add_upstream(name, upstream, platform, prefix, scratch)
            provides.append(name)

        if spec.get("npm_install"):
            install_from_lockfile(prefix, scratch)

        write_manifest(args.bundle, spec, platform, prefix, provides)

        archive = args.out / f"{args.bundle}-{platform}.tar.gz"
        # Sorted, with fixed ownership and timestamps: the same inputs should
        # produce the same bytes, or the digest we attest is noise.
        subprocess.run(  # noqa: S603
            [
                gnu_tar(), "--sort=name", "--owner=0", "--group=0", "--numeric-owner",
                "--mtime=@0", "--format=gnu", "-czf", str(archive), "-C", str(prefix), ".",
            ],
            check=True,
        )

    size = archive.stat().st_size / (1024 * 1024)
    print(f"  {archive.name}: {size:.1f} MB, provides {', '.join(sorted(provides))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

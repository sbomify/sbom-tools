#!/usr/bin/env python3
"""Test each bundle against real projects, in both CycloneDX and SPDX.

Building a bundle proves the archive assembles. It does not prove the tools
inside it can produce an SBOM of a real project, and every defect worth
finding so far has been of the second kind: the .NET SDK sitting at the
payload root rather than under bin/ so nothing reached PATH; sbt 2.x whose
launcher dies before a build loads; a Gradle plugin class spelled
CyclonedxPlugin rather than CycloneDxPlugin. Each of those assembled, verified
and published perfectly well.

So this clones real repositories, runs the bundle's own tools against them,
and checks the result is worth having. A zero-component SBOM is not an error
to any of these tools -- it validates and uploads and looks like success --
which is why every project has a floor rather than just an exit code.

    python tests/integration.py [--bundle jvm] [--project maven] [--dir DIR]

Bundles are taken from --dir if present (a local `out/`), otherwise downloaded
from the tools-rolling pre-release.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROJECTS = tomllib.loads((ROOT / "tests" / "projects.toml").read_text())["project"]
RELEASE_BASE = "https://github.com/sbomify/sbom-tools/releases/download"
CACHE = Path(os.environ.get("SBOM_TOOLS_CACHE", Path.home() / ".cache" / "sbom-tools-it"))


def log(message: str) -> None:
    print(message, flush=True)


@dataclass
class Bundle:
    """An unpacked bundle, described by its own bundle.toml."""

    name: str
    prefix: Path
    bin_dirs: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, name: str, prefix: Path) -> Bundle:
        body = tomllib.loads((prefix / "bundle.toml").read_text())
        return cls(
            name=name,
            prefix=prefix,
            bin_dirs=[str(d) for d in (body.get("bundle", {}).get("bin_dirs") or ["bin"])],
            env={k: str(v).replace("{prefix}", str(prefix)) for k, v in (body.get("env") or {}).items()},
        )

    def environment(self) -> dict[str, str]:
        """A clean environment, as a consumer would build it.

        HOME is deliberately somewhere writable but empty: the bundles are
        meant to work for a uid with no home directory, and a tool that
        quietly depends on ~/.m2 or ~/.gradle should fail here rather than in
        production.
        """
        path = os.pathsep.join(str(self.prefix / d) for d in self.bin_dirs)
        home = self.prefix / ".home"
        home.mkdir(exist_ok=True)
        return {
            "PATH": f"{path}{os.pathsep}/usr/bin:/bin",
            "HOME": str(home),
            "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
            "LANG": "C.UTF-8",
            **self.env,
        }


def fetch_bundle(name: str, arch: str, local: Path | None) -> Bundle:
    """Unpack a bundle, preferring a locally built one."""
    prefix = CACHE / "bundles" / f"{name}-{arch}"
    if (prefix / "bundle.toml").exists():
        return Bundle.load(name, prefix)

    archive = CACHE / f"{name}-linux-{arch}.tar.gz"
    if local and (local / archive.name).exists():
        archive = local / archive.name
        log(f"  using local {archive.name}")
    elif not archive.exists():
        url = f"{RELEASE_BASE}/tools-rolling/{name}-linux-{arch}.tar.gz"
        log(f"  downloading {name} bundle")
        archive.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url, timeout=600) as response:  # noqa: S310
            archive.write_bytes(response.read())

    prefix.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as tar:
        tar.extractall(prefix)  # noqa: S202 - our own published artifact
    return Bundle.load(name, prefix)


def clone(repo: str, ref: str) -> Path:
    """Shallow-clone a project, once, into the cache."""
    target = CACHE / "projects" / repo.replace("/", "_") / ref.replace("/", "_")
    if (target / ".sbom-clone").exists():
        return target
    shutil.rmtree(target, ignore_errors=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    log(f"  cloning {repo}@{ref}")
    result = subprocess.run(  # noqa: S603
        ["git", "clone", "--depth", "1", "--branch", ref, "--quiet",  # noqa: S607
         f"https://github.com/{repo}.git", str(target)],
        capture_output=True, text=True, timeout=3600,
    )
    if result.returncode != 0:
        raise RuntimeError(f"clone {repo}@{ref}: {result.stderr.strip()[:200]}")
    shutil.rmtree(target / ".git", ignore_errors=True)
    (target / ".sbom-clone").write_text(f"{repo}@{ref}\n")
    return target


def components(path: Path, fmt: str) -> int | None:
    """How many components a document declares, in either format."""
    if not path.exists():
        return None
    try:
        document = json.loads(path.read_text())
    except json.JSONDecodeError:
        return None
    if fmt == "spdx":
        # The document describes itself as a package too; it is not a
        # dependency, and counting it would make an empty SBOM look like a
        # result.
        packages = document.get("packages") or []
        described = set(document.get("documentDescribes") or [])
        return sum(1 for p in packages if p.get("SPDXID") not in described)
    return len(document.get("components") or [])


def run(cmd: list[str], cwd: Path, env: dict[str, str], timeout: int = 3600) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)  # noqa: S603


#: How each ecosystem is generated, per format. The JVM cases use the
#: ecosystem's own CycloneDX plugin rather than a generic scanner: measured on
#: real projects, the native plugin returns 106 components for
#: spring-petclinic against syft's 42, 340 for Keycloak against 92, and 288 for
#: okhttp against 34. cdxgen fails outright on all three, and trivy returns
#: zero for Gradle and sbt because `trivy fs` matches lock files and a JVM
#: source tree has none.
CYCLONEDX_MAVEN = "org.cyclonedx:cyclonedx-maven-plugin:2.9.1"
CYCLONEDX_GRADLE = "org.cyclonedx:cyclonedx-gradle-plugin:3.3.0"
SBT_SBOM = "0.6.0"

#: Applied through --init-script so the project's build file is never edited.
#: The class is CyclonedxPlugin, lowercase d -- the other spelling fails with
#: "unknown property 'org'", which reads like a classpath fault and is not one.
#: The plugin lives on the Gradle Plugin Portal; Maven Central does not have
#: 3.3.0 at all and its search index still answers 1.4.0.
GRADLE_INIT = """initscript {
  repositories { maven { url "https://plugins.gradle.org/m2/" }; mavenCentral() }
  dependencies { classpath "%s" }
}
allprojects { apply plugin: org.cyclonedx.gradle.CyclonedxPlugin }
""" % CYCLONEDX_GRADLE


def generate_maven(work: Path, env: dict[str, str], out: Path, fmt: str) -> int | None:
    # The project's own wrapper when it has one: a build pinned to an older
    # Maven should use it rather than whatever the bundle ships.
    wrapper = work / "mvnw"
    if wrapper.exists():
        wrapper.chmod(0o755)
    mvn = str(wrapper) if wrapper.exists() else "mvn"
    goal = f"{CYCLONEDX_MAVEN}:makeAggregateBom"
    run([mvn, "-B", "-q", "-N", goal, "-DoutputFormat=json", "-DoutputName=bom",
         f"-DschemaVersion={'1.6'}"], work, env)
    produced = work / "target" / "bom.json"
    if produced.exists():
        shutil.copy(produced, out)
    return components(out, fmt)


def generate_gradle(work: Path, env: dict[str, str], out: Path, fmt: str) -> int | None:
    init = work / "cdx-init.gradle"
    init.write_text(GRADLE_INIT)
    wrapper = work / "gradlew"
    if wrapper.exists():
        wrapper.chmod(0o755)
    gradle = str(wrapper) if wrapper.exists() else "gradle"
    run([gradle, "--no-daemon", "-I", str(init), "cyclonedxBom"], work, env)
    found = sorted(work.rglob("*bom.json"))
    if found:
        shutil.copy(found[0], out)
    return components(out, fmt)


def generate_sbt(work: Path, env: dict[str, str], out: Path, fmt: str) -> int | None:
    (work / "project").mkdir(exist_ok=True)
    (work / "project" / "sbom.sbt").write_text(f'addSbtPlugin("com.github.sbt" % "sbt-sbom" % "{SBT_SBOM}")\n')
    run(["sbt", "-batch", "makeBom"], work, env)
    found = [p for p in sorted(work.rglob("*.bom.json")) if p.name != "sbom.sbt"]
    if found:
        # Largest wins: a multi-module build writes one per module and the
        # root project's own is usually near-empty.
        found.sort(key=lambda p: (components(p, "cyclonedx") or 0), reverse=True)
        shutil.copy(found[0], out)
    return components(out, fmt)


def generate_cdxgen(
    work: Path, env: dict[str, str], out: Path, fmt: str,
    ecosystem: str | None = None, recurse: bool = False,
) -> int | None:
    cmd = ["cdxgen", "-o", str(out), "--fail-on-error"]
    if not recurse:
        cmd.append("--no-recurse")
    if fmt == "spdx":
        cmd += ["--format", "spdx"]
    if ecosystem:
        cmd += ["-t", ecosystem]
    cmd.append(".")
    run(cmd, work, env)
    return components(out, fmt)


def convert_to_spdx(cyclonedx: Path, out: Path, work: Path, env: dict[str, str]) -> int | None:
    """Turn a CycloneDX document into SPDX without losing anything.

    Used where the ecosystem's own tool emits CycloneDX only and the generic
    scanner cannot see the dependency graph. Measured on spring-petclinic:
    106 components in, 106 packages out, as SPDX-2.3.
    """
    run(["cyclonedx-cli", "convert", "--input-file", str(cyclonedx),
         "--output-file", str(out), "--output-format", "spdxjson"], work, env)
    return components(out, "spdx")


def generate_maven_spdx(work: Path, env: dict[str, str], out: Path, fmt: str) -> int | None:
    intermediate = out.with_suffix(".cdx.json")
    if generate_maven(work, env, intermediate, "cyclonedx") is None:
        return None
    return convert_to_spdx(intermediate, out, work, env)


def generate_sbt_spdx(work: Path, env: dict[str, str], out: Path, fmt: str) -> int | None:
    intermediate = out.with_suffix(".cdx.json")
    if generate_sbt(work, env, intermediate, "cyclonedx") is None:
        return None
    return convert_to_spdx(intermediate, out, work, env)


def generate_syft(work: Path, env: dict[str, str], out: Path, fmt: str) -> int | None:
    encoding = "spdx-json" if fmt == "spdx" else "cyclonedx-json"
    run(["syft", "scan", f"dir:{work}", "-o", f"{encoding}={out}"], work, env)
    return components(out, fmt)


def generate_gomod(work: Path, env: dict[str, str], out: Path, fmt: str) -> int | None:
    run(["cyclonedx-gomod", "mod", "-json", "-output", str(out), "-licenses=false", str(work)], work, env)
    return components(out, fmt)


def generate_cargo(work: Path, env: dict[str, str], out: Path, fmt: str) -> int | None:
    run(["cargo-cyclonedx", "cyclonedx", "--format", "json", "--override-filename", "bom"], work, env)
    found = sorted(work.rglob("bom.json"))
    if found:
        shutil.copy(found[0], out)
    return components(out, fmt)


#: (project, format) -> the generator that should produce it.
#:
#: Different tools per format is intentional. The CycloneDX plugins are the
#: ecosystem's own resolvers and win decisively for CycloneDX, but they emit
#: only CycloneDX; SPDX falls to whichever generic scanner reads that
#: ecosystem best. What matters is that each cell is the best available, not
#: that one tool covers everything.
GENERATORS = {
    ("maven", "cyclonedx"): generate_maven,
    ("maven-large", "cyclonedx"): generate_maven,
    ("gradle", "cyclonedx"): generate_gradle,
    ("sbt", "cyclonedx"): generate_sbt,
    ("go", "cyclonedx"): generate_gomod,
    ("rust", "cyclonedx"): generate_cargo,
    # SPDX from the native graph, not from a disk scan. syft finds 38 packages
    # in spring-petclinic and 92 in Keycloak because an unbuilt source tree has
    # no jars to catalog; converting the resolver's own output keeps all 106
    # and 340. Gradle is left on syft deliberately -- it reports 306 there,
    # ahead of the plugin's 288.
    ("maven", "spdx"): generate_maven_spdx,
    ("maven-large", "spdx"): generate_maven_spdx,
    ("sbt", "spdx"): generate_sbt_spdx,
}


def generator_for(project: str, fmt: str):
    """Which generator runs for this cell, and what it is called."""
    if (project, fmt) in GENERATORS:
        fn = GENERATORS[(project, fmt)]
        return fn, fn.__name__.removeprefix("generate_")
    # Everything else: cdxgen where it works, syft as the generic reader.
    if fmt == "spdx":
        return generate_syft, "syft"
    return generate_cdxgen, "cdxgen"


def run_case(name: str, spec: dict, fmt: str, local: Path | None, arch: str) -> tuple[str, int | None, int, bool]:
    bundle = fetch_bundle(spec["bundle"], arch, local)
    source = clone(spec["repo"], spec["ref"])
    if spec.get("subdir"):
        source = source / spec["subdir"]

    staging = CACHE / "work"
    staging.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(dir=staging)) / "p"
    try:
        shutil.copytree(source, work, ignore=shutil.ignore_patterns(".git"))
        out = work.parent / f"sbom.{fmt}.json"
        generate, label = generator_for(name, fmt)
        try:
            if generate is generate_cdxgen:
                count = generate(work, bundle.environment(), out, fmt,
                                 spec.get("cdxgen_type"), bool(spec.get("recurse", False)))
            else:
                count = generate(work, bundle.environment(), out, fmt)
        except Exception as exc:  # noqa: BLE001 - reported, not handled
            log(f"    {name}/{fmt}: {type(exc).__name__}: {str(exc)[:80]}")
            count = None
        floor = int(spec.get(f"floor_{fmt}", 1))
        return label, count, floor, count is not None and count >= floor
    finally:
        shutil.rmtree(work.parent, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", help="only projects served by this bundle")
    parser.add_argument("--project", help="only this project")
    parser.add_argument("--format", choices=("cyclonedx", "spdx"), help="only this format")
    parser.add_argument("--arch", default="amd64", choices=("amd64", "arm64"))
    parser.add_argument("--dir", type=Path, help="directory holding locally built bundles")
    args = parser.parse_args()

    formats = [args.format] if args.format else ["cyclonedx", "spdx"]
    selected = {
        n: s for n, s in PROJECTS.items()
        if (not args.bundle or s["bundle"] == args.bundle) and (not args.project or n == args.project)
    }
    if not selected:
        log("nothing selected")
        return 1

    CACHE.mkdir(parents=True, exist_ok=True)
    log(f"{'project':<14}{'bundle':<9}{'format':<11}{'generator':<12}{'count':>7}{'floor':>7}  verdict")
    log("-" * 76)
    failures = 0
    for name, spec in selected.items():
        for fmt in formats:
            label, count, floor, ok = run_case(name, spec, fmt, args.dir, args.arch)
            if not ok:
                failures += 1
            log(f"{name:<14}{spec['bundle']:<9}{fmt:<11}{label:<12}"
                f"{'-' if count is None else count:>7}{floor:>7}  {'ok' if ok else 'FAIL'}")
    total = len(selected) * len(formats)
    log("-" * 76)
    log(f"{total - failures}/{total} ok")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

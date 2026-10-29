"""Offline checks for the license database generator.

Run from the repository root:

    uv run --project licensedb pytest licensedb

The drift check is the one that matters. The generator's version lists live
here and the lifecycle table lives in sbomify-action, so a distro release added
to one and not the other drifts silently: a database built with no lifecycle
data attached, or a supported release that never gets a database at all. A
Dependabot bump of sbomify-action that brings a new release fails here, which
says exactly which repository config to add.
"""

from __future__ import annotations

import calendar
import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import generate  # noqa: E402
import matrix  # noqa: E402
from sbomify_action._enrichment.lifecycle_data import DISTRO_LIFECYCLE  # noqa: E402


def _end_of(value: str) -> date | None:
    """The last day a lifecycle date could mean: '2026-10' is all of October.

    lifecycle_data.py allows 'YYYY-MM-DD', 'YYYY-MM' and 'YYYY-Qn'. Resolving to
    the upper bound keeps "has this passed?" conservative.
    """
    text = value.strip()
    try:
        if len(text) == 10:
            return date.fromisoformat(text)
        if len(text) == 7 and text[4] == "-":
            year = int(text[:4])
            month = int(text[6]) * 3 if text[5] == "Q" else int(text[5:])
            return date(year, month, calendar.monthrange(year, month)[1])
    except ValueError:
        return None
    return None


def _generator_versions() -> dict[str, set[str]]:
    # Only distros where the generator pins an explicit per-version config are
    # comparable. Alpine builds its repository URL straight from the version
    # string, and Wolfi is a rolling release, so neither has a list of its own.
    versions = {
        "ubuntu": set(generate.UBUNTU_CODENAMES),
        "debian": set(generate.DEBIAN_CODENAMES),
    }
    for distro, repos in generate.RPM_DISTRO_REPOS.items():
        versions[distro] = set(repos)
    return versions


@pytest.mark.parametrize("distro", sorted(_generator_versions()))
def test_generator_and_lifecycle_table_agree(distro):
    built = _generator_versions()[distro]
    tracked = set(DISTRO_LIFECYCLE.get(distro, {}))

    untracked = sorted(built - tracked)
    assert not untracked, (
        f"{distro} {untracked}: the generator builds these but sbomify-action's lifecycle_data.py has no entry"
    )

    # Lifecycle data for a release the generator no longer builds is expected:
    # SBOMs of old images still name it. Only a supported one is a gap.
    today = date.today()
    missing = []
    for version in sorted(tracked - built):
        eol_raw = DISTRO_LIFECYCLE[distro][version].get("end_of_life")
        eol = _end_of(eol_raw) if eol_raw else None
        if eol is None or eol >= today:
            missing.append(version)
    assert not missing, (
        f"{distro} {missing}: sbomify-action tracks these and they are still supported, "
        f"but the generator has no repository configured for them"
    )


def test_matrix_covers_every_distro_the_generator_accepts():
    entries = matrix.build_matrix()
    assert len(entries) == len({(e["distro"], e["version"]) for e in entries}), "duplicate matrix entries"
    distros = {e["distro"] for e in entries}
    assert distros == {"alpine", "amazonlinux", "centos", "debian", "ubuntu", "rocky", "almalinux", "fedora", "wolfi"}


# sbomify-action looks packages up by these exact strings. A change here is a
# change to the database format and has to land in the action as well.
@pytest.mark.parametrize(
    "purl, expected",
    [
        (
            generate.make_apk_purl("musl", "1.2.5-r0", "3.20"),
            "pkg:apk/alpine/musl@1.2.5-r0?arch=x86_64&distro=alpine-3.20",
        ),
        (
            generate.make_deb_purl("bash", "5.2-1", "debian", "12"),
            "pkg:deb/debian/bash@5.2-1?arch=amd64&distro=debian-12",
        ),
        (
            generate.make_rpm_purl("bash", "5.1.8", "9.el9", "rocky", "9"),
            "pkg:rpm/rocky/bash@5.1.8-9.el9?arch=x86_64&distro=rocky-9",
        ),
        (
            generate.make_wolfi_purl("glibc", "2.40-r1"),
            "pkg:apk/wolfi/glibc@2.40-r1?arch=x86_64",
        ),
    ],
)
def test_purl_keys(purl, expected):
    assert purl == expected


def test_parse_apkindex():
    index = "P:musl\nV:1.2.5-r0\nL:MIT\n\nP:zlib\nV:1.3.1-r1\nL:Zlib\n"
    assert [p["P"] for p in generate.parse_apkindex(index)] == ["musl", "zlib"]


def test_parse_deb822_continuation_lines():
    text = "Package: bash\nDescription: GNU shell\n more text\n\nPackage: dash\n"
    stanzas = list(generate.parse_deb822(text))
    assert [s["Package"] for s in stanzas] == ["bash", "dash"]
    assert stanzas[0]["Description"] == "GNU shell\nmore text"

---
name: cut-release
description: Cut a new sbom-tools release and write its release notes. Thin pointer to the org-wide sbomify release skill, plus the facts specific to this repo. Use whenever the user says "cut a release", "ship a release", "tag a release", "make a new release", or asks for release notes.
---

# Cut a release

The release process is shared by every repo in the `sbomify` org and lives in
one place: the **`sbomify-release`** skill, kept in the sbomify knowledge base
under `skills/release/` (`SKILL.md` for the process, `repos.md` for per-repo
profiles). Load and follow it. Do not copy its steps here: copies drift.

If the `sbomify-release` skill is not installed for you, ask a maintainer for
access rather than improvising a process.

## What is specific to this repo

The shared skill's `repos.md` has the full profile. The essentials:

- **Version:** CalVer `YY.MM.MICRO`, mandatory for every sbomify repo
  ([ADR-0002](https://github.com/sbomify/adr/blob/master/0002-adopt-calver-versioning.md)).
- **Release PR** bumps the version in `Cargo.toml` and `package.json` and
  refreshes their lockfiles with `cargo` and `bun`.
- `master` publishes the `rolling` pre-release in place. A published release
  is immutable: **publishing it builds and uploads the bundles**
  (`.github/workflows/build.yml`, `licensedb.yml`), and they cannot change
  afterwards. Create the release as a draft and publish only once `master` is
  green and the bundle set is right.
- Notes open with `Immutable toolchain bundles, built from <sha>.`, then list
  tool changes, with CVE or GO advisory ids for security fixes.
- sbomify-action pins releases of this repo, so release here before bumping
  that pin.

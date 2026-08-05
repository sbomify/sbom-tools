# sbom-tools

The SBOM tooling [sbomify-action](https://github.com/sbomify/sbomify-action)
runs, built from source and published with build provenance.

| tool | pinned in |
| --- | --- |
| [syft](https://github.com/anchore/syft) | `go.mod` |
| [cosign](https://github.com/sigstore/cosign) | `go.mod` |
| [crane](https://github.com/google/go-containerregistry) | `go.mod` |
| [cyclonedx-gomod](https://github.com/CycloneDX/cyclonedx-gomod) | `go.mod` |
| [cargo-cyclonedx](https://github.com/CycloneDX/cyclonedx-rust-cargo) | `Cargo.lock` |

Nothing here is a library. The manifests exist so each tool is pinned in the
package manager its own ecosystem uses, where Dependabot maintains it, rather
than in a bespoke version file nothing watches.

## Why this is a separate repository

These binaries used to be built inside sbomify-action, which made the action's
release the only way to publish them. That is circular: the action fetches its
tools from a release that only exists once the action has released. It also
meant bumping syft required cutting an action release, and buried two dozen
tool binaries in the release list of a repository that is not about tools.

Splitting them apart gives the tools their own cadence, and makes the
attestation signer a genuinely separate identity from the thing it vouches for.

## Bundles

Consumers fetch one archive per ecosystem. Each holds the tools built here
plus the toolchain they shell out to, unpacks anywhere writable, and runs
without root.

| bundle | contents | measured |
| --- | --- | ---: |
| `go` | cyclonedx-gomod + Go toolchain | 72.7 MB |
| `rust` | cargo-cyclonedx + cargo, rustc | |
| `jvm` | cdxgen + JDK, Maven, Gradle, sbt | 430.4 MB |
| `dotnet` | cdxgen + .NET SDK | |
| `cdxgen` | cdxgen alone | 33.9 MB |
| `syft` | syft | 27.1 MB |
| `sigstore` | cosign, crane | |

The JVM is one bundle rather than three because all of Maven, Gradle and sbt
need the same 190MB JDK.

Every archive carries a `bundle.toml` describing what it provides, which
directories hold executables, and what environment to set, so a consumer
unpacks it and reads what to do rather than being taught each layout.

## Where the versions live

Nothing here restates a version that a package manager already owns, because
a literal is a pin no bot can see — and a stale pin never fails, since a tool
that is still downloadable never complains about being old.

| pinned in | maintained by | covers |
| --- | --- | --- |
| `go.mod` | Dependabot `gomod` | syft, cosign, crane, cyclonedx-gomod, the Go toolchain |
| `Cargo.lock` | Dependabot `cargo` | cargo-cyclonedx |
| `bun.lock` | Dependabot `bun` | cdxgen |
| `global.json` | Dependabot `dotnet-sdk` | the .NET SDK |
| `bun.lock` | Dependabot `bun` | cdxgen |
| `bundles.toml` | `scripts/check_tool_versions.py` | the JDK, bun, Maven, Gradle, sbt, Rust |

The last row is the residue, and it is all *runtimes* rather than our tools:
no Dependabot ecosystem covers a JDK, a bun or Maven or Gradle distribution,
an sbt launcher or a Rust toolchain. Those stay literal and are watched by a
script instead.

Everything in the rows above is one of our own tools, and every one of them
is pinned by the package manager that owns it — nothing here maintains a
second, parallel pin. cdxgen was the last exception: it shipped as upstream's
prebuilt binary under a sha256 of our own, and now comes from `bun.lock`,
which records a sha512 for it and 197 other packages and refuses anything
that does not match.

The bundle stays self-contained. `bun install --frozen-lockfile` runs when
the bundle is *assembled*, not when it is fetched — what ships is bun plus a
populated `node_modules`, ready to run with nothing to install.

URLs for the manifest-driven pins are templated on `{version}`, so a bump
reaches the download. The digest beside it does **not** follow, which is why
`scripts/check_digests.py` runs in CI — it downloads every pinned asset and
says exactly which digest needs refreshing, rather than letting a release
discover it. `--update` rewrites them.

## Releases

| trigger | published to |
| --- | --- |
| push to `master` | the `tools-rolling` pre-release, replaced in place |
| published tag | that release's assets, immutable |

`tools-rolling` is what lets master run against a freshly bumped tool before a
release is cut. Cutting a release to find out whether a bump works is
backwards: the release is the thing the bump might break. It is a pre-release
so it never displaces the real latest release, and it is not a supported
download.

Every binary ships next to its Sigstore bundle:

```
syft-linux-amd64
syft-linux-amd64.sigstore.json
```

## Verifying

```console
$ cosign verify-blob-attestation \
    --bundle syft-linux-amd64.sigstore.json \
    --new-bundle-format \
    --type slsaprovenance1 \
    --certificate-identity-regexp '^https://github\.com/sbomify/sbom-tools/\.github/workflows/build\.yml@refs/(heads/master|tags/.+)$' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    syft-linux-amd64
```

`--new-bundle-format` and `--type slsaprovenance1` are both required: cosign v3
validates `--type` against the predicate type, and
`actions/attest-build-provenance` emits `https://slsa.dev/provenance/v1`, which
cosign aliases to `slsaprovenance1`.

The bundle carries the subject digest inside the signed statement, so this
checks a digest that was signed rather than one copied into a file by hand.
That is why consumers pin no digest of their own.

## What is deliberately not here

Language runtimes and SDKs — Go, Rust, the JDK, Maven — and cdxgen. Runtimes
are what the tools above shell out to, and building a JDK or rustc from source
to avoid trusting a vendor is not a trade worth making. cdxgen is a bundled
Node application that resolves data files against `__dirname`, so a plain
`bun build --compile` of the published package yields a binary that dies with
`ENOENT: /data/lic-mapping.json`; upstream needs a 599-line build script in a
distro container to produce theirs, and a worse copy of an artifact they
already test helps nobody.

Consumers pin those upstream, by digest.

## Integration tests

Building a bundle proves the archive assembles. It does not prove the tools
inside it can produce an SBOM of a real project, and every defect worth
finding so far has been of the second kind — the .NET SDK sitting at the
payload root so nothing reached `PATH`, sbt 2.x whose launcher dies before a
build loads, a Gradle plugin class spelled `CyclonedxPlugin` rather than
`CycloneDxPlugin`. Each of those assembled, verified and published perfectly
well.

`tests/integration.py` clones real repositories, runs each bundle's tools
against them, and checks the result is worth having:

```console
$ python tests/integration.py --bundle jvm
project       bundle   format     generator     count  floor  verdict
maven         jvm      cyclonedx  maven           106     40  ok
maven         jvm      spdx       maven_spdx      106     40  ok
maven-large   jvm      cyclonedx  maven           340    200  ok
...
```

Every project has a floor because a zero-component SBOM is not an error to
any of these tools — it validates, it uploads, and it looks like success.
Floors catch "empty" and "collapsed", not small changes in what upstream
reports.

### Both formats, best tool for each

A bundle should answer either question well, and the best tool differs:

| ecosystem | CycloneDX | SPDX |
| --- | --- | --- |
| Maven | cyclonedx-maven-plugin | converted from it |
| Gradle | cyclonedx-gradle-plugin | converted from it |
| sbt | sbt-sbom | converted from it |
| Go | cyclonedx-gomod | converted from it |
| Rust | cargo-cyclonedx | converted from it |
| everything else | cdxgen | syft |

Wherever an ecosystem has its own resolver, SPDX is converted from that
rather than scanned for — the resolver knows the dependency graph and a
scanner is guessing at it from files on disk.

Comparing the two directly is what settled it, and the counts alone were
misleading. syft reports **more** packages than the Gradle plugin for
okhttp, 306 against 288, and the two sets turn out to be **completely
disjoint**: syft's are `@colors/colors` and `@jridgewell/*`, because okhttp
carries a JavaScript toolchain for its docs. It was cataloguing
`node_modules`, not Java. For hugo and fd syft is a strict superset whose
extras are `actions/checkout` and `actions/setup-go` — GitHub Actions from
`.github/workflows`, which are not part of the shipped software.

Conversion uses syft, which is already in every bundle. cyclonedx-cli is
marginally more faithful (106 packages at 100% purls against 108 at 99%)
but is a 77MB self-contained .NET binary, which is a poor trade for one
percent.

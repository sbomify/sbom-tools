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

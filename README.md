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

| bundle | contents | size |
| --- | --- | ---: |
| `go` | cyclonedx-gomod + Go toolchain | 99.9 MiB |
| `rust` | cargo-cyclonedx + cargo, rustc | 176.1 MiB |
| `jvm` | cdxgen + JDK, Maven, Gradle, sbt | 466.7 MiB |
| `dotnet` | cdxgen + .NET SDK | 289.0 MiB |
| `php` | cdxgen + PHP, Composer | 78.0 MiB |
| `cdxgen` | cdxgen alone | 70.3 MiB |
| `syft` | syft | 27.1 MiB |
| `sigstore` | cosign, crane | 32.9 MiB |

Sizes are the `linux-amd64` archive. `linux-arm64` is smaller in every case,
by 3% for `jvm` and 20% for `rust`. The darwin archives are not listed because
nothing has measured them yet; every build prints the size and digest of each
archive it produces in its run summary, which is a better place to read them
than a number here that goes stale.

### Which bundle an ecosystem needs

Mirrors [Supported Lockfiles](https://github.com/sbomify/sbomify-action/#supported-lockfiles)
in sbomify-action, which is the list this repository exists to serve. Read it
the other way round from the table above: a consumer knows what it has
checked out, not which tool it wants.

| Language | Files | bundle |
| --- | --- | --- |
| Python | `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `pyproject.toml` | none -- cyclonedx-py is pure Python and ships in the image |
| JavaScript | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` | `cdxgen` |
| Java | `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile` | `jvm` |
| Go | `go.mod`, `go.sum` | `go` |
| Rust | `Cargo.lock` | `rust` |
| Ruby | `Gemfile.lock` | `cdxgen` |
| PHP | `composer.lock` | `cdxgen` |
| PHP | `composer.json` (no lock file) | `php` |
| .NET/C# | `packages.lock.json` | `dotnet` |
| Swift | `Package.swift`, `Package.resolved` | `syft` |
| Dart | `pubspec.lock` | `cdxgen` |
| Elixir | `mix.lock` | `cdxgen` |
| Scala | `build.sbt` | `jvm` |
| C++ | `conan.lock` | `cdxgen` |
| Terraform | `.terraform.lock.hcl` | `syft` |

Six languages share the `cdxgen` bundle because cdxgen reads their lock files
directly and needs none of their toolchains: a PHP or Ruby project is parsed
without PHP or Ruby installed. The bundles that carry a toolchain do so
because their generator shells out to it -- cyclonedx-gomod runs `go list`,
and the Maven and Gradle plugins run inside the build.

Two rows are honest gaps rather than choices. **Swift** has no maintained
CycloneDX generator: cyclonedx-cocoapods covers CocoaPods only, and the one
SwiftPM project died in 2021, so Swift falls to syft and produces a thinner
SBOM than the rest. **Terraform** has no native generator either. Both work;
neither is as good as what the other ecosystems get.

`syft` also serves every ecosystem for SPDX where the native tool emits only
CycloneDX, which is most of them -- see the format table in sbomify-action.
`sigstore` generates nothing; it is how a consumer verifies these bundles
before trusting them.

The JVM is one bundle rather than three because all of Maven, Gradle and sbt
need the same 190MB JDK.

Every archive carries a `bundle.toml` describing what it provides, which
directories hold executables, and what environment to set, so a consumer
unpacks it and reads what to do rather than being taught each layout.

## Platforms

Each bundle is published four times:

| platform | archive | built on |
| --- | --- | --- |
| `linux-amd64` | `jvm-linux-amd64.tar.gz` | `ubuntu-latest` |
| `linux-arm64` | `jvm-linux-arm64.tar.gz` | `ubuntu-24.04-arm` |
| `darwin-amd64` | `jvm-darwin-amd64.tar.gz` | `macos-15-intel` |
| `darwin-arm64` | `jvm-darwin-arm64.tar.gz` | `macos-15` |

Darwin is here because these tools are useful to a person before they are
useful to a pipeline. A consumer who wants to see what an SBOM of their
project looks like, or why the one CI produced came back empty, should be able
to run the same tools CI ran without getting a container involved -- and a
developer debugging a local SBOM against a different syft than the pipeline
used is debugging the wrong thing.

Every platform is built on a runner of its own kind rather than
cross-compiled. Rust and PHP leave no choice: neither can be built for macOS
without Apple's SDK. The Go tools could have been cross-compiled, but their
smoke test is executing them, and a build that cannot run what it produced
proves the least about the platform that has never been tested.

`bundle.toml` carries `os` and `arch`, so a consumer picks a bundle by
comparing them against its own `uname` rather than parsing the file name.

### What "self-contained" means on a Mac

The Linux binaries here are statically linked, and the build refuses one that
is not: an unpacked bundle has no idea which libc the container around it has.
That property is unavailable on macOS -- Apple ships no `libSystem.a` and the
linker refuses `-static`, so a Mach-O binary cannot be fully static. What is
available is the same guarantee stated differently: everything the binary
loads comes from the operating system, which every Mac has by definition.
`.github/actions/assert-self-contained` checks it with `otool -L` and fails on
any path outside `/usr/lib` and `/System/Library`.

That check earns its keep on exactly one failure, and it is the likely one: a
Homebrew path. A build machine has `/opt/homebrew` and a consumer does not, so
a link against it works perfectly in CI and dies on the first Mac that
downloads the result. PHP is where this nearly happened -- its `openssl`
extension is what lets Composer reach packagist, macOS has no OpenSSL to link
against, and Homebrew's is a dylib under `/opt/homebrew`. The build passes
Homebrew's `libssl.a` and `libcrypto.a` explicitly so OpenSSL ends up inside
the binary, the same place Alpine's `openssl-libs-static` puts it in the Linux
build -- same outcome, and the only reason it needs saying is that the macOS
default would have been the dylib.

Nothing here is notarized, and there is no Developer ID certificate behind it.
The binaries carry the ad-hoc signatures their linkers produce, which is what
arm64 requires in order to execute at all and nothing more. In practice that
is enough, because `curl` and `tar` do not set the quarantine attribute --
Gatekeeper only involves itself in files a browser or an installer marked. A
bundle downloaded through a browser needs one command before it will run:

```console
$ xattr -dr com.apple.quarantine <prefix>
```

The provenance attestation beside each archive is the real check anyway, and
it says more than notarization does: `cosign verify-blob-attestation` ties the
archive to the workflow, repository and commit that built it.

### Where the layouts differ

Two vendors ship macOS differently enough to matter, and both are normalised
during assembly so a bundle has one shape on every platform:

* Temurin's macOS JDK is an application bundle -- `Contents/Home/{bin,lib}`
  under the version-named wrapper. `payload = "Contents/Home"` takes the
  inside of it, so `jdk/bin/java` and `JAVA_HOME={prefix}/jdk` mean the same
  thing everywhere and `bundle.toml` carries one value rather than two.
* Microsoft spells macOS "osx" in its asset names. The .NET SDK's layout is
  otherwise identical, entry point at the payload root, so `bin_dir` already
  covers it.

Maven, Gradle, sbt and `composer.phar` are JVM applications or bytecode: one
archive serves all four platforms, and all four entries in `bundles.toml` name
it with the same digest.

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

Every artifact ships next to its Sigstore bundle, one pair per platform:

```
syft-linux-amd64.tar.gz
syft-linux-amd64.tar.gz.sigstore.json
syft-darwin-arm64.tar.gz
syft-darwin-arm64.tar.gz.sigstore.json
```

## Verifying

```console
$ cosign verify-blob-attestation \
    --bundle syft-darwin-arm64.tar.gz.sigstore.json \
    --new-bundle-format \
    --type slsaprovenance1 \
    --certificate-identity-regexp '^https://github\.com/sbomify/sbom-tools/\.github/workflows/build\.yml@refs/(heads/master|tags/.+)$' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    syft-darwin-arm64.tar.gz
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

Windows, too, and not for lack of demand: every bundle would need a third
answer to how a tool is made self-contained, the PHP build has no counterpart
there at all, and the unit of distribution stops being a tarball that unpacks
anywhere. Darwin was worth that cost because it is where the people who read
these SBOMs work; a Windows bundle would be a second port carrying the first
one's assumptions.

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
$ python tests/integration.py --bundle jvm --os darwin --arch arm64
platform darwin-arm64
project       bundle   format     generator     count  floor  verdict
maven         jvm      cyclonedx  maven           106     40  ok
maven         jvm      spdx       maven_spdx      106     40  ok
maven-large   jvm      cyclonedx  maven           340    200  ok
...
```

`--os` and `--arch` pick which bundle to test, and the harness refuses one
whose `bundle.toml` describes a different platform rather than running the
wrong binaries. All four are tested in CI, because macOS is where the
toolchains a bundle carries actually differ -- a different JDK layout, a
different .NET SDK, a `php` linked another way -- and those are the
differences assembling an archive cannot catch.

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

#!/bin/sh
# Compile the pinned PHP release into a static binary for one architecture.
#
#   scripts/build_php.sh <goarch> <output-path>
#
# In a file rather than inline in build.yml so the cache key can name it.
# Everything that decides what the binary contains lives here or in
# php-release.json, so hashing those two is enough to say "this is the same
# build" -- keying on the workflow file instead would rebuild PHP whenever any
# unrelated job changed.
#
# Compiled rather than downloaded because php.net publishes no Linux binaries,
# only source. The alternative was a third party's static build, which would
# have been the only component here not coming from its own vendor.
#
# Inside Alpine so it links against musl, which is what makes the result
# static-pie and therefore relocatable into any container. Building on the
# runner's glibc would produce a binary tied to that glibc.
set -eu

GOARCH="$1"
OUTPUT="$2"

read_pin() {
    python3 -c "import json;print(json.load(open('php-release.json'))$1)"
}

VERSION=$(read_pin "['php']['version']")
SHA=$(read_pin "['php']['sha256']")
IMAGE=$(read_pin "['builder']['image']+'@'+json.load(open('php-release.json'))['builder']['digest']")

OUT_DIR=$(CDPATH= cd -- "$(dirname -- "$OUTPUT")" && pwd)
OUT_NAME=$(basename -- "$OUTPUT")

echo "building php $VERSION for $GOARCH in $IMAGE"

docker run --rm -v "$OUT_DIR:/out" "$IMAGE" sh -eu -c "
    apk add --no-cache build-base autoconf curl file re2c bison linux-headers \
      openssl-dev openssl-libs-static zlib-dev zlib-static binutils >/dev/null
    cd /tmp
    curl -sSLo php.tar.gz 'https://www.php.net/distributions/php-$VERSION.tar.gz'
    echo '$SHA  php.tar.gz' | sha256sum -c -
    tar xzf php.tar.gz && cd php-$VERSION
    # Only what Composer needs to run and resolve:
    #   phar    - composer ships as one
    #   openssl - packagist over HTTPS
    #   zlib    - compressed transfers
    #   iconv   - composer refuses to start without iconv or mbstring,
    #             and iconv is in musl while mbstring would pull in
    #             oniguruma
    #   filter/ctype/tokenizer - composer's own requirements
    # Extensions a *project* declares are irrelevant: nothing is installed
    # here, only resolved. Verified against guzzle, Slim and laravel/framework,
    # where this build returns exactly what Debian's full-featured php-cli
    # returns.
    ./configure \
      --disable-all --disable-cgi --disable-phpdbg --enable-cli \
      --enable-phar --enable-filter --enable-ctype --enable-tokenizer \
      --with-iconv --with-openssl --with-zlib --without-pear \
      --enable-static --disable-shared >/dev/null
    # -all-static is libtool's spelling; plain -static in LDFLAGS is dropped
    # and yields a dynamically linked binary.
    make -j\"\$(nproc)\" LDFLAGS=-all-static >/dev/null
    strip sapi/cli/php
    cp sapi/cli/php '/out/$OUT_NAME'
"

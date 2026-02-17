#!/bin/bash

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"

. "$EXEDIR/common.inc"

BASEURL=https://github.com/bol-van/musl-cross/releases/download/latest

[ -d "$TOOLCHAINS" ] || mkdir -p "$TOOLCHAINS"

ask_target 1

pushd "$TOOLCHAINS"
for t in $TGT; do
	[ -d "$t" ] && rm -r "$t"
	curl -Lo - "${BASEURL}/${t}.tar.xz" | tar -Jx
done
popd

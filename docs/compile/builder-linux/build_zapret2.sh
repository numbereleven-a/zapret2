#!/bin/bash

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"

. "$EXEDIR/common.inc"

ZDIR="zapret2"
ZBASE="$EXEDIR"
BRANCH=master
ZURL=https://github.com/bol-van/zapret2/archive/refs/heads/${BRANCH}.zip
ZBIN="$EXEDIR/binaries"

dl_zapret2()
{
	if [ -d "$ZBASE/$ZDIR" ]; then
		dir_is_not_empty "$ZBASE/$ZDIR" && {
			echo "zapret2 dir is not empty. if you want to redownload - delete it."
			return
		}
		rmdir "$ZBASE/$ZDIR"
	fi
	pushd "$ZBASE"
	curl -Lo /tmp/zapret2.zip "$ZURL"
	unzip /tmp/zapret2.zip
	rm /tmp/zapret2.zip
	mv zapret2-${BRANCH} $ZDIR
	popd
}

translate_target()
{
	case $1 in
		aarch64-unknown-linux-musl)
			ZBINTARGET=linux-arm64
			;;
		arm-unknown-linux-musleabi)
			ZBINTARGET=linux-arm
			;;
		x86_64-unknown-linux-musl)
			ZBINTARGET=linux-x86_64
			;;
		i586-unknown-linux-musl)
			ZBINTARGET=linux-x86
			;;
		mips-unknown-linux-muslsf)
			ZBINTARGET=linux-mips
			;;
		mipsel-unknown-linux-muslsf)
			ZBINTARGET=linux-mipsel
			;;
		mips64-unknown-linux-musl)
			ZBINTARGET=linux-mips64
			;;
		mips64el-unknown-linux-musl)
			ZBINTARGET=linux-mipsel64
			;;
		powerpc-unknown-linux-musl)
			ZBINTARGET=linux-ppc
			;;
		riscv64-unknown-linux-musl)
			ZBINTARGET=linux-riscv64
			;;
		*)
			return 1
	esac
	return 0
}

dl_zapret2
check_toolchains
ask_target

[ -d "$ZBIN" ] || mkdir -p "$ZBIN"

for t in $TGT; do
	buildenv $t

	translate_target $t || {
		echo COULD NOT TRANSLATE TARGET $t TO BIN DIR
		continue
	}

	pushd $ZBASE/$ZDIR

	LUA_JIT=0
	LCFLAGS="-I${STAGING_DIR}/include/lua${LUA_VER}"
	LLIB="-L${STAGING_DIR}/lib -llua"
	target_has_luajit $t && {
		LUA_JIT=1
		LCFLAGS="-I${STAGING_DIR}/include/luajit-${LUAJIT_VER}"
		LLIB="-L${STAGING_DIR}/lib -lluajit-${LUAJIT_LUAVER}"
	}

	OPTIMIZE=-Oz \
	CFLAGS="-static-libgcc -static -I$STAGING_DIR/include $CFLAGS" \
	LDFLAGS="-L$DEPS_DIR/lib $LDFLAGS" \
	make LUA_JIT=$LJIT LUA_CFLAGS="$LCFLAGS" LUA_LIB="$LLIB"

	[ -d "$ZBIN/$ZBINTARGET" ] || mkdir "$ZBIN/$ZBINTARGET"
	cp -f binaries/my/* "$ZBIN/$ZBINTARGET"

	popd

	buildenv_clear
done


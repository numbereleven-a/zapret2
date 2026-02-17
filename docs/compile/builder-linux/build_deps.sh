#!/bin/bash

EXEDIR="$(dirname "$0")"
EXEDIR="$(cd "$EXEDIR"; pwd)"

. "$EXEDIR/common.inc"

dl_deps()
{
	if [ -d "$DEPS" ]; then
		dir_is_not_empty "$DEPS" && {
			echo "deps dir is not empty. if you want to redownload - delete it."
			return
		}
	else
		mkdir "$DEPS"
	fi
	pushd "$DEPS"
	curl -Lo - https://www.netfilter.org/pub/libnfnetlink/libnfnetlink-1.0.2.tar.bz2 | tar -xj
	curl -Lo - https://www.netfilter.org/pub/libmnl/libmnl-1.0.5.tar.bz2 | tar -xj
	curl -Lo - https://www.netfilter.org/pub/libnetfilter_queue/libnetfilter_queue-1.0.5.tar.bz2 | tar -xj
	curl -Lo - https://zlib.net/zlib-1.3.1.tar.gz | tar -xz
	curl -Lo - https://github.com/openresty/luajit2/archive/refs/tags/v${LUAJIT_RELEASE}.tar.gz | tar -xz
	curl -Lo - https://www.lua.org/ftp/lua-${LUA_RELEASE}.tar.gz | tar -xz
	popd
}

build_netlink()
{
	for i in libmnl libnfnetlink libnetfilter_queue ; do
		(
		cd $i-*
		[ -f "Makefile" ] && make clean
		CFLAGS="$MINSIZE $CFLAGS" \
		LDFLAGS="$LDMINSIZE $LDFLAGS" \
		./configure --prefix= --host=$TARGET CC=$CC LD=$LD --enable-static --disable-shared --disable-dependency-tracking
		make install -j$nproc DESTDIR=$STAGING_DIR
		)
		sed -i "s|^prefix=.*|prefix=$STAGING_DIR|g" $STAGING_DIR/lib/pkgconfig/$i.pc
	done
}
build_zlib()
{
(
cd zlib-*
[ -f "Makefile" ] && make clean
CFLAGS="$MINSIZE $CFLAGS" \
LDFLAGS="$LDMINSIZE $LDFLAGS" \
./configure --prefix= --static
make install -j$nproc DESTDIR=$STAGING_DIR
)
}
build_lua()
{
(
	cd lua-${LUA_RELEASE}
	make clean
	make CC="$CC" AR="$AR rc" CFLAGS="$MINSIZE $CFLAGS" LDFLAGS="$LDMINSIZE $LDFLAGS" linux -j$nproc
	make install INSTALL_TOP="$STAGING_DIR" INSTALL_BIN="$STAGING_DIR/bin" INSTALL_INC="$STAGING_DIR/include/lua${LUA_VER}" INSTALL_LIB="$STAGING_DIR/lib"
)
}
build_luajit()
{
(
	cd luajit2-*
	make clean
	make BUILDMODE=static XCFLAGS=-DLUAJIT_DISABLE_FFI HOST_CC="$HOST_CC" CROSS= CC="$CC" TARGET_AR="$AR rcus" TARGET_STRIP=$STRIP TARGET_CFLAGS="$MINSIZE $CFLAGS" TARGET_LDFLAGS="$LDMINSIZE $LDFLAGS"
	make install PREFIX= DESTDIR="$STAGING_DIR"
)
}
build_luajit_for_target()
{
	target_has_luajit $1 && {
		case "$1" in
			*64*)
				HOST_CC="$HOSTCC"
				;;
			*)
				HOST_CC="$HOSTCC -m32"
				;;
		esac
			build_luajit
	}
}

dl_deps
check_toolchains
ask_target

for t in $TGT; do
	buildenv $t
	pushd "$DEPS"
	bsd_files
	build_netlink
	build_zlib
	build_lua
	build_luajit_for_target $t
	popd
	buildenv_clear
done

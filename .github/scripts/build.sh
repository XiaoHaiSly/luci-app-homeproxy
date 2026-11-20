#!/bin/bash

set -o errexit
set -o pipefail

FORMATS="${1:-all}"
RELEASE_TYPE="${2:-snapshot}"
VERSION_OVERRIDE="${3:-}"

case "$FORMATS" in
	all) FORMATS="apk ipk" ;;
	apk|ipk) ;;
	*) echo "Unknown format: $FORMATS (use all, apk or ipk)." >&2; exit 1 ;;
esac

export PKG_SOURCE_DATE_EPOCH="$(date "+%s")"
export SOURCE_DATE_EPOCH="$PKG_SOURCE_DATE_EPOCH"

BASE_DIR="$(cd "$(dirname "$0")"; pwd)"
PKG_DIR="$(cd "$BASE_DIR/../../luci-app-homeproxy"; pwd)"

function get_mk_value() {
	awk -F "$1:=" '{print $2}' "$PKG_DIR/Makefile" | xargs
}

function get_mk_depends() {
	sed -n '/^LUCI_DEPENDS:=/,/[^\\]$/p' "$PKG_DIR/Makefile" |
		sed -e 's/^LUCI_DEPENDS:=//' -e 's/\\$//' |
		tr -s ' \t\n' ' ' |
		tr -d '+' |
		xargs
}

PKG_NAME="$(get_mk_value "PKG_NAME")"
if [ -z "$PKG_NAME" ]; then
	echo "Failed to read PKG_NAME from $PKG_DIR/Makefile." >&2
	exit 1
fi

PKG_DESC="$(get_mk_value "LUCI_TITLE")"
PKG_ARCH="$(get_mk_value "LUCI_PKGARCH")"
PKG_ARCH="${PKG_ARCH:-all}"

PKG_REPO="$(git -C "$PKG_DIR" remote get-url origin 2>"/dev/null" |
	sed -e 's/\.git$//' -e 's,^git@github\.com:,https://github.com/,' || echo "")"
PKG_MAINTAINER="$(git -C "$PKG_DIR" log -1 --format='%an <%ae>' 2>"/dev/null" || echo "Unknown")"

if [ -n "$VERSION_OVERRIDE" ]; then
	PKG_VERSION="${VERSION_OVERRIDE#v}"
elif [ "$RELEASE_TYPE" == "release" ]; then
	PKG_VERSION="$(git -C "$PKG_DIR" describe --tags --always 2>"/dev/null" || echo "0.0.0")"
	PKG_VERSION="${PKG_VERSION#v}"
else
	PKG_VERSION="$(date -u "+%Y.%m.%d")-r$(git -C "$PKG_DIR" rev-list --count HEAD 2>"/dev/null" || echo 0)"
fi
PKG_VERSION="$(echo -e "$PKG_VERSION" | tr -c 'A-Za-z0-9.+~_-' '.' | sed -e 's/^\.*//' -e 's/\.*$//')"
if [ -z "$PKG_VERSION" ]; then
	PKG_VERSION="0.0.0"
fi

PKG_DEPENDS="libc luci-base $(get_mk_depends)"

TEMP_DIR="$(mktemp -d -p "$BASE_DIR")"
trap 'rm -rf "$TEMP_DIR"' EXIT

STAGE_DIR="$TEMP_DIR/stage"
mkdir -p "$STAGE_DIR/lib/upgrade/keep.d/"
mkdir -p "$STAGE_DIR/usr/lib/lua/luci/i18n/"
mkdir -p "$STAGE_DIR/www/"

cp -fpR "$PKG_DIR/htdocs"/* "$STAGE_DIR/www/"
cp -fpR "$PKG_DIR/root"/* "$STAGE_DIR/"

cat > "$STAGE_DIR/lib/upgrade/keep.d/$PKG_NAME" <<-EOF
/etc/homeproxy/certs/
/etc/homeproxy/dashboard/
/etc/homeproxy/ruleset/
/etc/homeproxy/resources/direct_list.txt
/etc/homeproxy/resources/proxy_list.txt
EOF

if [ -f "$PKG_DIR/po/zh_Hans/homeproxy.po" ]; then
	po2lmo "$PKG_DIR/po/zh_Hans/homeproxy.po" "$STAGE_DIR/usr/lib/lua/luci/i18n/homeproxy.zh-cn.lmo"
fi

function build_apk() {
	local pkg_tree="$TEMP_DIR/apk/$PKG_NAME"
	local scripts="$TEMP_DIR/apk-scripts"
	mkdir -p "$TEMP_DIR/apk" "$scripts"
	cp -a "$STAGE_DIR" "$pkg_tree"
	mkdir -p "$pkg_tree/lib/apk/packages/"

	find "$pkg_tree" -type f,l -printf '/%P\n' | sort > "$pkg_tree/lib/apk/packages/$PKG_NAME.list"

	echo "/etc/config/homeproxy" > "$pkg_tree/lib/apk/packages/$PKG_NAME.conffiles"
	while IFS= read -r file; do
		[ -f "$pkg_tree/$file" ] || continue
		sha256sum "$pkg_tree/$file" | sed "s,$pkg_tree/,," >> "$pkg_tree/lib/apk/packages/$PKG_NAME.conffiles_static"
	done < "$pkg_tree/lib/apk/packages/$PKG_NAME.conffiles"

	echo -e '#!/bin/sh
[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
export root="${IPKG_INSTROOT}"
export pkgname="'"$PKG_NAME"'"
add_group_and_user
default_postinst
[ -n "${IPKG_INSTROOT}" ] || { rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	killall -HUP rpcd 2>/dev/null
	exit 0
}' > "$scripts/post-install"

	echo -e '#!/bin/sh
export PKG_UPGRADE=1
[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
export root="${IPKG_INSTROOT}"
export pkgname="'"$PKG_NAME"'"
add_group_and_user
default_postinst
[ -n "${IPKG_INSTROOT}" ] || { rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	killall -HUP rpcd 2>/dev/null
	exit 0
}' > "$scripts/post-upgrade"

	echo -e '#!/bin/sh
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
export root="${IPKG_INSTROOT}"
export pkgname="'"$PKG_NAME"'"
default_prerm' > "$scripts/pre-deinstall"
	chmod 0755 "$scripts"/*

	local sign_args=()
	if [ -n "${APK_SIGN_KEY:-}" ]; then
		sign_args=(--sign-key "$APK_SIGN_KEY")
		echo "Signing apk with $APK_SIGN_KEY."
	else
		echo "No APK_SIGN_KEY set, building an unsigned apk (install it with --allow-untrusted)."
	fi

	apk mkpkg \
		--info "name:$PKG_NAME" \
		--info "version:$PKG_VERSION" \
		--info "description:$PKG_DESC" \
		--info "arch:noarch" \
		--info "origin:${PKG_REPO:-$PKG_NAME}" \
		--info "url:$PKG_REPO" \
		--info "maintainer:$PKG_MAINTAINER" \
		--info "depends:$PKG_DEPENDS" \
		--script "post-install:$scripts/post-install" \
		--script "post-upgrade:$scripts/post-upgrade" \
		--script "pre-deinstall:$scripts/pre-deinstall" \
		"${sign_args[@]}" \
		--files "$pkg_tree" \
		--output "$TEMP_DIR/apk/${PKG_NAME}_${PKG_VERSION}.apk"

	mv -f "$TEMP_DIR/apk/${PKG_NAME}_${PKG_VERSION}.apk" "$BASE_DIR/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.apk"
	echo "Built: ${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.apk"
}

function build_ipk() {
	local pkg_tree="$TEMP_DIR/ipk/$PKG_NAME"
	mkdir -p "$TEMP_DIR/ipk"
	cp -a "$STAGE_DIR" "$pkg_tree"
	mkdir -p "$pkg_tree/CONTROL/"

	cat > "$pkg_tree/CONTROL/control" <<-EOF
		Package: $PKG_NAME
		Version: $PKG_VERSION
		Depends: $(echo "$PKG_DEPENDS" | sed 's/ /, /g')
		Source: $PKG_REPO
		SourceName: $PKG_NAME
		Section: luci
		SourceDateEpoch: $PKG_SOURCE_DATE_EPOCH
		Maintainer: $PKG_MAINTAINER
		Architecture: $PKG_ARCH
		Installed-Size: TO-BE-FILLED-BY-IPKG-BUILD
		Description:  $PKG_DESC
	EOF
	chmod 0644 "$pkg_tree/CONTROL/control"

	echo "/etc/config/homeproxy" > "$pkg_tree/CONTROL/conffiles"

	echo -e '#!/bin/sh
[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
default_postinst $0 $@' > "$pkg_tree/CONTROL/postinst"
	chmod 0755 "$pkg_tree/CONTROL/postinst"

	cat > "$pkg_tree/CONTROL/postinst-pkg" <<-EOF
		[ -n "\${IPKG_INSTROOT}" ] || {
			(. /etc/uci-defaults/$PKG_NAME) && rm -f /etc/uci-defaults/$PKG_NAME
			rm -f /tmp/luci-indexcache
			rm -rf /tmp/luci-modulecache/
			exit 0
		}
	EOF
	chmod 0755 "$pkg_tree/CONTROL/postinst-pkg"

	echo -e '#!/bin/sh
[ -s ${IPKG_INSTROOT}/lib/functions.sh ] || exit 0
. ${IPKG_INSTROOT}/lib/functions.sh
default_prerm $0 $@' > "$pkg_tree/CONTROL/prerm"
	chmod 0755 "$pkg_tree/CONTROL/prerm"

	ipkg-build -m "" "$pkg_tree" "$TEMP_DIR/ipk"

	mv -f "$TEMP_DIR/ipk/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.ipk" "$BASE_DIR/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.ipk"
	echo "Built: ${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.ipk"
}

for fmt in $FORMATS; do
	"build_$fmt"
done

echo "Version: $PKG_VERSION"
echo "Depends: $PKG_DEPENDS"

# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022-2023 ImmortalWrt.org

include $(TOPDIR)/rules.mk

LUCI_TITLE:=The modern ImmortalWrt proxy platform for ARM64/AMD64
LUCI_PKGARCH:=all
LUCI_DEPENDS:= \
	+luci-base \
	+sing-box \
	+firewall4 \
	+ip-full \
	+kmod-tun \
	+curl \
	+flock \
	+unzip \
	+ucode-mod-digest

LUCI_EXTRA_DEPENDS:=sing-box (>=1.14.0)
PKG_NAME:=luci-app-homeproxy

define Package/luci-app-homeproxy/conffiles
/etc/config/homeproxy
/etc/homeproxy/cache/
/etc/homeproxy/certs/
/etc/homeproxy/ruleset/
/etc/homeproxy/dashboard/
/etc/homeproxy/resources/direct_list.txt
/etc/homeproxy/resources/proxy_list.txt
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature

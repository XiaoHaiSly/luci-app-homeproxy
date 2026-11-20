include $(TOPDIR)/rules.mk

PKG_NAME:=hiddify-core
PKG_VERSION:=5.9.15
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/hiddify/hiddify-core.git
PKG_SOURCE_VERSION:=v$(PKG_VERSION)
PKG_MIRROR_HASH:=skip

PKG_LICENSE:=GPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE.md
PKG_MAINTAINER:=Hiddify <wrt@hiddify.com>

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=github.com/hiddify/hiddify-core
GO_PKG_BUILD_PKG:=$(GO_PKG)/cmd/main
# -checklinkname=0 is required by the badlinkname/tfogo_checklinkname0 tags
GO_PKG_LDFLAGS:=-s -w -checklinkname=0
GO_PKG_LDFLAGS_X:= \
	$(GO_PKG)/v2/hcommon/constants.Version=$(PKG_VERSION) \
	github.com/sagernet/sing-box/constant.Version=$(PKG_VERSION)
GO_PKG_TAGS:=badlinkname,tfogo_checklinkname0,with_acme,with_awg,with_bond,with_call,with_ccm,with_clash_api,with_cloudflared,with_conntrack,with_dhcp,with_embedded_tor,with_grpc,with_gvisor,with_kcp,with_low_memory,with_masque,with_ocm,with_openconnect,with_openvpn,with_quic,with_sudoku,with_tailscale,with_usbip,with_utls,with_v2ray_api,with_wireguard,with_xdrive

export GIT_CONFIG_COUNT:=2
export GIT_CONFIG_KEY_0:=url.https://github.com/.insteadOf
export GIT_CONFIG_VALUE_0:=git@github.com:
export GIT_CONFIG_KEY_1:=url.https://github.com/.insteadOf
export GIT_CONFIG_VALUE_1:=ssh://git@github.com/

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/hiddify-core
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=Hiddify universal proxy platform
  URL:=https://hiddify.com/
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle +kmod-inet-diag +kmod-tun +firewall4 +kmod-nft-queue
endef

define Package/hiddify-core/description
  Hiddify is a universal proxy platform built on sing-box: Hysteria, SOCKS, Shadowsocks,
  ShadowTLS, Tor, Trojan, VLESS, VMess, WireGuard, WARP, Psiphon and more, from a config file
  or a subscription link.
endef

define Package/hiddify-core/conffiles
/etc/config/hiddify-core
/etc/hiddify-core/config.json
endef

define Package/hiddify-core/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/main $(1)/usr/bin/hiddify-core
	$(INSTALL_DIR) $(1)/etc/hiddify-core
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/release/config/config.json $(1)/etc/hiddify-core/config.json
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/hiddify-core.conf $(1)/etc/config/hiddify-core
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/hiddify-core.init $(1)/etc/init.d/hiddify-core
endef

$(eval $(call GoBinPackage,hiddify-core))
$(eval $(call BuildPackage,hiddify-core))

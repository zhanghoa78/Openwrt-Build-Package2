include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-tcpdump
PKG_VERSION:=1.0
PKG_RELEASE:=1

LUCI_TITLE:=TCPDump Web Interface
LUCI_DEPENDS:=+tcpdump +rpcd
LUCI_PKGARCH:=all
LUCI_DESCRIPTION:=Web interface for tcpdump packet capture

include $(TOPDIR)/feeds/luci/luci.mk

define Package/luci-app-tcpdump/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./files/luci/controller/tcpdump.lua $(1)/usr/lib/lua/luci/controller/
	
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/tcpdump
	$(INSTALL_DATA) ./files/luci/view/tcpdump/index.htm $(1)/usr/lib/lua/luci/view/tcpdump/
	
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./files/acl.d/tcpdump.json $(1)/usr/share/rpcd/acl.d/
	
	$(INSTALL_DIR) $(1)/usr/libexec/rpcd
	$(INSTALL_BIN) ./files/rpcd/luci_tcpdump.lua $(1)/usr/libexec/rpcd/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))

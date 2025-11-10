#
# Copyright (C) 2023 Your Name <your.email@example.com>
#
# This is free software, licensed under the Apache License, Version 2.0 .
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-tcpdump
PKG_VERSION:=2.0  # 版本号提升，因为有重要功能更新
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-tcpdump
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=TCPDump Web Interface (with bridge capture support)
  URL:=https://github.com/your-repo/luci-app-tcpdump  # 建议添加项目地址
  MAINTAINER:=Your Name <your.email@example.com>      # 建议添加维护者信息
  # 核心依赖: luci-base (LuCI框架), tcpdump (抓包工具)
  # 新增依赖: ebtables (用于捕获桥接流量)
  DEPENDS:=+luci-base +tcpdump +ebtables
  PKGARCH:=all
endef

define Package/luci-app-tcpdump/description
  A powerful web interface for tcpdump packet capture.
  Includes advanced features like bridge traffic tapping via ebtables.
endef

# 这里不需要 Build/Configure 和 Build/Compile，因为我们只有静态文件和Lua脚本

define Package/luci-app-tcpdump/install
	# 创建目标目录
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/tcpdump
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view/tcpdump/assets

	# 使用 $(CP) 复制文件，这是更标准和可靠的方式
	# 假设你的源文件都放在包目录下的 files/ 目录中
	# 这种结构更清晰，符合 OpenWrt 打包惯例
	$(CP) ./files/usr/lib/lua/luci/controller/tcpdump.lua $(1)/usr/lib/lua/luci/controller/
	$(CP) ./files/usr/lib/lua/luci/view/tcpdump/overview.htm $(1)/usr/lib/lua/luci/view/tcpdump/
	$(CP) ./files/www/luci-static/resources/view/tcpdump/assets/tcpdump.css $(1)/www/luci-static/resources/view/tcpdump/assets/
endef

$(eval $(call BuildPackage,luci-app-tcpdump))

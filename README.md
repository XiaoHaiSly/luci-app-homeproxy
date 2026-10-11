# luci-app-homeproxy

基于 [homeproxy](https://github.com/immortalwrt/homeproxy) 修改的 OpenWrt 代理客户端，以 [sing-box](https://github.com/shtorm-7/sing-box-extended) 为核心，提供 LuCI 管理界面。

本仓库包含两个软件包：

| 目录 | 说明 |
| --- | --- |
| `luci-app-homeproxy/` | LuCI 界面与服务脚本 |
| `sing-box/` | sing-box-extended 核心 |

## 主要增强

- **DNS Fallback**：主 DNS 与国内 DNS 均可配置多个备用服务器，支持 DNS 劫持
- **XHTTP 支持**，新一代 Xray 传输方式
- **sing-box 面板**：内置 Dashboard sing-box官方面板
- **TUN 模式**：统一使用 TUN 入站并启用 `auto_redirect`，TCP/UDP 均由 sing-box 处理
- **分流规则**：按服务单独指定出口。内置 YouTube、TikTok、Telegram、Twitter/X、Google、Cloudflare、GitHub、AI 服务（非大陆）等预设，也可自定义规则；每条规则可单独选择走主节点、独立 URLTest、指定节点、直连或拒绝，并同步为该规则的域名选用对应的 DNS。支持拖动排序和单条启停，规则按顺序匹配。
- **在线更新核心**：可在界面中更新 sing-box 核心
- 缓存与配置加载流程优化，提高运行稳定性

## TUN 模式

在 Linux 上，sing-box 官方推荐的透明代理方式就是 TUN 配合 `auto_redirect`。本项目统一采用这一方案，用户不必再在多个模式之间选择：

- **TCP + UDP 全支持**：redirect 模式只能处理 TCP；TUN 一个模式即可同时覆盖 TCP 和 UDP。
- **性能更好**：sing-box 官方文档指出，`auto_redirect` 提供更好的路由和更高的性能（优于 tproxy），并能避免 TUN 与 Docker 桥接网络之间的冲突。
- **国内直连**：绕过大陆模式下，sing-box 启动时会根据 `geoip-cn` 规则集生成 nftables 规则（规则集更新时自动刷新），目的地为国内 IP 的连接直接放行，不再交给 sing-box 处理，节省 CPU。

## 运行要求

- OpenWrt / ImmortalWrt（需使用 firewall4）
- **sing-box-extended ≥ 1.14.0**（官方版本缺少部分功能，请使用本仓库 `sing-box/` 编译的版本，或自行引用本仓库进行编译）

### 从源码编译

将本仓库放入 OpenWrt 源码或 SDK 的 `package/` 目录（或添加为 feed），然后：

```sh
make menuconfig
make package/luci-app-homeproxy/compile V=s
make package/sing-box/compile V=s
```

`sing-box` 的 Makefile 提供精简构建选项（`SING_BOX_TINY_BUILD_*`），可在 menuconfig 中按需裁剪功能以减小体积。

## 与上游的差异

- 移除了 redirect / tproxy 等旧代理模式，统一使用 TUN（原因见上文）。升级时迁移脚本会自动清理旧版本遗留的选项，并将代理模式设为 TUN。
- 核心要求提升到 sing-box-extended ≥ 1.14.0。

## 许可证与致谢

本项目以 GPL-2.0 协议发布，详见 [LICENSE](LICENSE)。

- [immortalwrt/homeproxy](https://github.com/immortalwrt/homeproxy)：本项目的上游
- [shtorm-7/sing-box](https://github.com/shtorm-7/sing-box-extended)：代理核心

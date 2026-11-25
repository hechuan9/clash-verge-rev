# VPN

Clash Verge Home 的「VPN」页管理一个 WireGuard 出口。从侧栏导入 `.conf`，填写站点清单，然后点「应用配置」。每行一个域名或 URL。`*.example.com` 匹配主域名和子域名。匹配的站点优先走 WireGuard，其他流量继续按订阅规则转发。

支持单对端 IPv4 配置。`[Interface]` 需要 `Address`（含 CIDR）和 `PrivateKey`，可选 `DNS` 和 `MTU`。`[Peer]` 需要 `PublicKey`、`Endpoint` 和 `AllowedIPs = 0.0.0.0/0`，可选 `PresharedKey` 和 `PersistentKeepalive`。配置与密钥保存在应用数据目录的 `vpn.json`，请勿提交到仓库。

- [VpnPage.tsx](VpnPage.tsx) 负责配置导入和站点编辑。
- [config.rs](config.rs) 处理导入校验、存储、运行配置注入和失败回滚。
- 共享接线位于 [侧栏路由](../../pages/_navigation.tsx)、[Tauri 命令注册](../../../src-tauri/src/ipc.rs) 和 [配置生成](../../../src-tauri/src/enhance/mod.rs)。

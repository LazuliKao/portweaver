# PortWeaver
Port forwarding utils for OpenWrt

## 配置文件

每条“项目/规则”需要包含以下字段：

- 备注
- 地址族限制：`IPv4 和 IPv6` / `IPv4` / `IPv6`
- 协议：`TCP+UDP` / `TCP` / `UDP`
- 监听端口：例如 `3389`
- reuseaddr：是否绑定到本地端口
- 目标地址
- 目标端口：例如 `3389`
- 打开防火墙端口
- 添加防火墙转发

### UCI（OpenWrt）配置示例

建议使用 `/etc/config/portweaver`，一个 section 对应一个项目/规则：

```uci
config project 'rdp'
	option remark 'Windows RDP'
	option family 'IPv4'
	option protocol 'TCP'
	option listen_port '3389'
	option reuseaddr '1'
	option target_address '192.168.1.100'
	option target_port '3389'
	option open_firewall_port '1'
	option add_firewall_forward '1'
```

支持的 option key（同义词）大致如下：

- `remark`/`note`/`备注`
- `family`/`addr_family`/`地址族限制`
- `protocol`/`proto`/`协议`
- `listen_port`/`src_port`/`监听端口`
- `reuseaddr`/`reuse`/`reuse_addr`/`绑定到本地端口`
- `target_address`/`target_addr`/`dst_ip`/`目标地址`
- `target_port`/`dst_port`/`目标端口`
- `open_firewall_port`/`firewall_open`/`打开防火墙端口`
- `add_firewall_forward`/`firewall_forward`/`添加防火墙转发`

### JSON 配置（可选）

JSON 配置默认**不编译进二进制**（用于减小体积）。

启用方式：

```sh
zig build -Djson=true
```

JSON 文件格式：顶层可以是 `projects` 数组，或直接是数组。

```json
{
	"projects": [
		{
			"remark": "Windows RDP",
			"family": "IPv4",
			"protocol": "TCP",
			"listen_port": 3389,
			"reuseaddr": true,
			"target_address": "192.168.1.100",
			"target_port": 3389,
			"open_firewall_port": true,
			"add_firewall_forward": true
		}
	]
}
```

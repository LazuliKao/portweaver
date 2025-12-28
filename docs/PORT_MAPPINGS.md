# 端口范围和端口映射功能说明

## 概述

PortWeaver 现在支持两种端口转发模式：

1. **单端口模式** - 传统的一对一端口映射
2. **端口映射模式** - 支持端口范围和多端口映射

这两种模式是**互斥**的，每个 project 只能选择其中一种。

## 单端口模式

### JSON 配置
```json
{
  "projects": [
    {
      "remark": "HTTP转发",
      "target_address": "127.0.0.1",
      "listen_port": 8080,
      "target_port": 80,
      "protocol": "tcp",
      "family": "any",
      "enable_app_forward": true
    }
  ]
}
```

### UCI 配置
```uci
config project 'http'
    option remark 'HTTP转发'
    option listen_port '8080'
    option target_address '127.0.0.1'
    option target_port '80'
    option protocol 'tcp'
```

## 端口映射模式

### 功能特性

- **端口范围转发**：将一段连续的端口映射到另一段端口
- **多端口映射**：在一个 project 中配置多个独立的端口映射
- **每个映射独立协议**：每个映射可以单独设置 TCP/UDP/BOTH

### JSON 配置示例

#### 1. 端口范围转发
```json
{
  "projects": [
    {
      "remark": "范围端口转发",
      "target_address": "192.168.1.100",
      "family": "any",
      "enable_app_forward": true,
      "port_mappings": [
        {
          "listen_port": "8080-8090",
          "target_port": "80-90",
          "protocol": "tcp"
        }
      ]
    }
  ]
}
```

这将创建以下映射：
- 8080 → 80
- 8081 → 81
- 8082 → 82
- ...
- 8090 → 90

#### 2. 多端口映射
```json
{
  "projects": [
    {
      "remark": "游戏服务器",
      "target_address": "192.168.1.200",
      "family": "any",
      "enable_app_forward": true,
      "port_mappings": [
        {
          "listen_port": "25565",
          "target_port": "25565",
          "protocol": "tcp"
        },
        {
          "listen_port": "19132",
          "target_port": "19132",
          "protocol": "udp"
        },
        {
          "listen_port": "8123",
          "target_port": "8123",
          "protocol": "both"
        }
      ]
    }
  ]
}
```

### UCI 配置示例

#### 1. 端口范围转发
```uci
config project 'web_cluster'
    option remark 'Web服务器集群'
    option target_address '192.168.1.100'
    option family 'any'
    option enable_app_forward '1'

config port_mapping
    option project 'web_cluster'
    option listen_port '8080-8090'
    option target_port '80-90'
    option protocol 'tcp'
```

#### 2. 多端口映射
```uci
config project 'game_server'
    option remark '游戏服务器'
    option target_address '192.168.1.200'
    option enable_app_forward '1'

config port_mapping
    option project 'game_server'
    option listen_port '25565'
    option target_port '25565'
    option protocol 'tcp'

config port_mapping
    option project 'game_server'
    option listen_port '19132'
    option target_port '19132'
    option protocol 'udp'
```

## LuCI 界面使用

### 创建单端口转发

1. 在 "Port Forwarding Projects" 中添加新项目
2. 填写基本信息（Remark、Target Address 等）
3. 确保 "Use Multi-Port Mode" 开关为**关闭**状态
4. 填写 "Listen Port" 和 "Target Port"
5. 选择 Protocol（TCP/UDP/TCP+UDP）
6. 保存配置

### 创建端口映射（多端口模式）

1. 在 "Port Forwarding Projects" 中添加新项目
2. 填写基本信息（Remark、Target Address 等）
3. **开启** "Use Multi-Port Mode" 开关
4. 在下方出现的 "Port Mappings" 表格中点击添加
5. 为每个映射填写：
   - Listen Port(s)：监听端口（如 "8080" 或 "8080-8090"）
   - Target Port(s)：目标端口（如 "80" 或 "80-90"）
   - Protocol：协议类型
6. 可以添加多个映射
7. 保存配置

### 界面特性

- **模式切换开关**：在项目表单内部，可以方便地切换单端口和多端口模式
- **动态表单**：切换模式后，表单会自动显示/隐藏对应的字段
- **内嵌端口映射管理**：多端口模式下，端口映射列表直接显示在项目表单内
- **实时验证**：输入端口时会实时验证格式和范围
- **自动关联**：端口映射自动关联到父项目，删除项目时自动清理
- **预览显示**：项目列表中直观显示当前使用的模式和配置概要

## 字段说明

### port_mappings（JSON）/ port_mapping（UCI）

| 字段 | 类型 | 说明 | 示例 |
|------|------|------|------|
| listen_port | string/int | 监听端口或端口范围 | "8080" 或 "8080-8090" |
| target_port | string/int | 目标端口或端口范围 | "80" 或 "80-90" |
| protocol | string | 协议类型 | "tcp", "udp", "both" |
| project (仅UCI) | string | 关联的项目名称 | "web_cluster" |

### 验证规则

1. **端口范围验证**
   - 格式：单个端口或 "起始端口-结束端口"
   - 端口范围：1-65535
   - 起始端口必须小于结束端口

2. **端口数量匹配**
   - listen_port 和 target_port 的端口数量必须相同
   - 例如：`8080-8090` (11个端口) 必须对应 `80-90` (11个端口)

3. **模式互斥**
   - 不能同时设置 `listen_port/target_port` 和 `port_mappings`
   - 违反此规则将导致配置错误

## 注意事项

1. **性能考虑**
   - 端口范围转发会为每个端口创建独立的转发线程
   - 建议范围不要过大（推荐 < 100 个端口）

2. **防火墙规则**
   - 防火墙规则支持端口范围语法（如 "8080-8090"）
   - 每个映射会独立创建防火墙规则

3. **应用层转发**
   - 端口范围模式下，每个端口独立转发
   - UDP 转发使用单一 socket，但端口独立处理

4. **配置迁移**
   - 旧的单端口配置完全兼容
   - 可以逐步迁移到端口映射模式

## 示例场景

### 场景 1：Docker 容器端口映射
```json
{
  "remark": "Docker容器集群",
  "target_address": "192.168.1.50",
  "port_mappings": [
    {
      "listen_port": "8000-8009",
      "target_port": "8000-8009",
      "protocol": "tcp"
    }
  ]
}
```

### 场景 2：Minecraft 服务器（TCP + UDP）
```json
{
  "remark": "Minecraft服务器",
  "target_address": "192.168.1.100",
  "port_mappings": [
    {
      "listen_port": "25565",
      "target_port": "25565",
      "protocol": "tcp"
    },
    {
      "listen_port": "19132",
      "target_port": "19132",
      "protocol": "udp"
    }
  ]
}
```

### 场景 3：开发环境端口段
```json
{
  "remark": "开发环境",
  "target_address": "localhost",
  "enable_app_forward": true,
  "port_mappings": [
    {
      "listen_port": "3000-3010",
      "target_port": "3000-3010",
      "protocol": "tcp"
    },
    {
      "listen_port": "4200-4210",
      "target_port": "4200-4210",
      "protocol": "tcp"
    }
  ]
}
```

## 故障排查

### 配置无效
- 检查是否同时设置了单端口和端口映射模式
- 确保端口范围的起始端口小于结束端口
- 验证监听端口和目标端口的数量是否匹配

### 转发不工作
- 检查 `enable_app_forward` 是否启用
- 验证防火墙规则是否正确生成
- 检查目标地址是否可达
- 查看系统日志获取详细错误信息

### 端口冲突
- 确保监听端口范围没有与其他服务冲突
- 检查是否有重复的端口映射配置

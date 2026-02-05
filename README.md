# AnthropicProxy

一个 Windows 平台的 API 协议转换代理工具，支持将 OpenAI API 格式的请求转换为 Anthropic API 格式，实现不同 AI 服务之间的协议兼容。

## 功能特性

- **协议转换**：支持 OpenAI ↔ Anthropic API 格式互转
- **多平台支持**：代理 `api.openai.com`、`api.anthropic.com`、`generativelanguage.googleapis.com`
- **流式响应**：完整支持 SSE (Server-Sent Events) 流式输出
- **模型映射**：支持自定义模型名称映射
- **工具调用**：支持 Function Calling / Tool Use 转换
- **图形界面**：基于 Walk 的 Windows 原生 GUI
- **系统托盘**：支持最小化到托盘运行
- **证书管理**：自动生成和管理 HTTPS 代理证书
- **单实例运行**：防止程序重复启动

## 系统要求

- Windows 7 及以上版本
- 管理员权限（用于修改 hosts 文件和安装证书）

## 快速开始

### 1. 下载运行

直接运行 `AnthropicProxy.exe`，程序会自动以管理员权限启动。

### 2. 安装证书

首次使用需要安装代理 CA 证书：
1. 点击「生成证书」按钮生成证书文件
2. 点击「安装证书」将 CA 证书添加到系统信任存储

### 3. 配置代理

- **目标服务器**：设置后端 API 服务地址
- **监听地址**：本地代理监听地址（默认 127.0.0.1）
- **转换协议**：选择协议转换模式
  - `OpenAI 直连`：直接转发 OpenAI 格式请求
  - `Anthropic 转换`：将 OpenAI 格式转换为 Anthropic 格式

### 4. 启动代理

点击「启动代理」按钮开始代理服务。

## 配置文件

配置保存在 `config.json`：

```json
{
  "target_url": "https://api.example.com",
  "listen_addr": "127.0.0.1",
  "protocol_mode": 1,
  "model_mappings": {
    "source-model-name": "target-model-name"
  }
}
```

| 字段 | 说明 |
|------|------|
| `target_url` | 后端 API 服务器地址 |
| `listen_addr` | 本地监听地址 |
| `protocol_mode` | 协议模式：0=OpenAI直连，1=Anthropic转换 |
| `model_mappings` | 模型名称映射表 |

## 模型映射

支持将请求中的模型名称映射为其他名称，在「模型映射」标签页中配置：

- 点击「添加映射」创建新的映射规则
- 双击已有规则进行编辑
- 选中后点击「删除映射」移除规则

## 工作原理

1. 程序修改系统 hosts 文件，将目标域名指向本地
2. 在本地 443 端口启动 HTTPS 代理服务器
3. 拦截 API 请求，进行协议转换
4. 将转换后的请求发送到实际的后端服务器
5. 将响应转换回原始格式返回给客户端

## 构建

### 依赖

```bash
go get github.com/lxn/walk
go get github.com/lxn/win
```

### 编译

```bash
# 生成资源文件
go-winres make

# 编译（无控制台窗口）
go build -ldflags="-H windowsgui" -o AnthropicProxy.exe .
```

## 目录结构

```
AnthropicProxy/
├── main.go              # 主程序源码
├── config.json          # 配置文件
├── icon.ico             # 程序图标（可选）
├── certs/               # 证书目录
│   ├── proxy_ca.crt     # CA 证书
│   ├── proxy_ca.key     # CA 私钥
│   └── cert_*.crt/key   # 域名证书
└── winres/              # Windows 资源配置
    └── winres.json
```

## 注意事项

1. **管理员权限**：程序需要管理员权限来修改 hosts 文件和安装证书
2. **证书信任**：首次使用需要安装并信任代理 CA 证书
3. **防火墙**：确保防火墙允许程序监听 443 端口
4. **单实例**：程序只允许运行一个实例

## 故障排除

### 程序无法启动
- 检查是否已有实例在运行
- 确保以管理员权限运行

### 代理无法工作
- 检查证书是否已正确安装
- 确认 hosts 文件已正确修改
- 查看日志输出了解详细错误信息

### 客户端连接失败
- 确保客户端信任了代理 CA 证书
- 检查目标服务器地址是否正确

## 许可证

MIT License

## 致谢

- [lxn/walk](https://github.com/lxn/walk) - Windows GUI 框架
- [go-winres](https://github.com/tc-hib/go-winres) - Windows 资源编译工具

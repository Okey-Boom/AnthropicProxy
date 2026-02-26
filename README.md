# AnthropicProxy

一个 Windows 平台的 API 协议转换代理工具，支持 OpenAI、Anthropic、Gemini 三种 API 协议之间的透明转换，通过本地 HTTPS 劫持实现无感代理。

## 功能特性

- **多协议转换**：支持 OpenAI / Anthropic / Gemini 三种 API 格式互转
- **三种代理模式**：
  - `OpenAI (直连)` — 直接转发 OpenAI 格式请求
  - `Anthropic (Claude)` — 将 OpenAI 格式转换为 Anthropic 格式
  - `OpenAI (转换)` — 将请求转换为标准 OpenAI 格式发送
- **多域名代理**：劫持 `api.openai.com`、`api.anthropic.com`、`generativelanguage.googleapis.com`
- **流式响应**：完整支持 SSE (Server-Sent Events) 流式输出
- **模型映射**：自定义模型名称映射，自动注入映射模型到模型列表（支持 OpenAI / Anthropic / Gemini 格式）
- **工具调用**：支持 Function Calling / Tool Use 跨协议转换
- **请求重试**：网络错误、超时、5xx、429 等场景自动重试（指数退避）
- **日志管理**：可选 GUI 实时显示或输出到本地日志文件，启动时自动清空日志文件
- **图形界面**：基于 Walk 的 Windows 原生 GUI，支持最小化到系统托盘
- **证书管理**：自动生成和管理 HTTPS 代理 CA 及域名证书
- **单实例运行**：防止程序重复启动
- **崩溃保护**：异常时自动保存崩溃日志到 `crash.log`

## 系统要求

- Windows 7 及以上版本
- 管理员权限（用于修改 hosts 文件和安装证书）

## 快速开始

### 1. 下载运行

直接运行 `AnthropicProxy.exe`，程序会自动以管理员权限启动。

### 2. 安装证书

点击「安装证书」按钮，程序会自动完成以下操作：
1. 生成 CA 根证书和各域名证书
2. 将 CA 证书添加到系统信任存储
3. 修改 hosts 文件将目标域名指向本地

### 3. 配置代理

- **目标服务器**：设置后端 API 服务地址
- **监听地址**：本地代理监听地址（默认 `127.0.0.1`）
- **转换协议**：选择协议转换模式

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
  },
  "show_log": true
}
```

| 字段 | 说明 |
|------|------|
| `target_url` | 后端 API 服务器地址 |
| `listen_addr` | 本地监听地址 |
| `protocol_mode` | 协议模式：`0` = OpenAI 直连，`1` = Anthropic 转换，`2` = OpenAI 转换 |
| `model_mappings` | 模型名称映射表 |
| `show_log` | 日志显示方式：`true` = GUI 显示，`false` = 输出到日志文件 |

## 模型映射

在「模型映射」标签页中管理映射规则：

- 右键点击表格打开上下文菜单，支持「添加映射」「编辑映射」「删除映射」
- 点击列标题可按源模型名称或目标模型名称排序
- 映射的源模型会自动注入到 API 返回的模型列表中（支持 OpenAI、Anthropic、Gemini 三种格式）
- 请求中带有 `provider/model` 前缀的模型名称会自动去除前缀后再匹配映射规则

## 日志管理

通过按钮栏的「显示日志」复选框切换日志模式：

- **勾选**：日志在 GUI 窗口中实时显示
- **不勾选**：日志输出到程序运行目录下的 `AnthropicProxy.log` 文件，窗口自动缩小

日志文件在每次程序启动时自动清空。

## 工作原理

1. 修改系统 hosts 文件，将目标域名（`api.openai.com` 等）指向 `127.0.0.1`
2. 在本地 443 端口启动 HTTPS 代理服务器，使用自签名 CA 证书
3. 拦截 API 请求，根据选择的协议模式进行格式转换
4. 对请求中的模型名称进行映射替换
5. 将转换后的请求发送到实际的后端服务器
6. 将响应转换回原始格式返回给客户端
7. 程序退出时自动恢复 hosts 文件并移除 CA 证书

## 构建

### 依赖

```bash
go get github.com/lxn/walk
go get github.com/lxn/win
```

### 编译

```bash
# 生成 Windows 资源文件
go-winres make

# 编译
go build -trimpath -ldflags="-s -w -H windowsgui" -o AnthropicProxy.exe .
```

## 目录结构

```
AnthropicProxy/
├── main.go                # 主程序源码
├── config.json            # 运行时配置文件
├── icon.ico               # 程序图标
├── AnthropicProxy.log     # 日志文件（日志输出到文件时生成）
├── crash.log              # 崩溃日志（异常时生成）
├── certs/                 # 证书目录（首次安装时生成）
│   ├── proxy_ca.crt       # CA 根证书
│   ├── proxy_ca.key       # CA 私钥
│   └── cert_*.crt/key     # 各域名证书
└── winres/                # Windows 资源配置
    ├── winres.json
    ├── icon.png
    └── icon16.png
```

## 注意事项

1. **管理员权限**：程序需要管理员权限来修改 hosts 文件和安装证书
2. **证书信任**：首次使用需要安装并信任代理 CA 证书
3. **防火墙**：确保防火墙允许程序监听 443 端口
4. **单实例**：程序只允许运行一个实例
5. **代理软件**：如使用 v2rayN 等代理工具，需将目标域名设置为直连（`direct`）

## 故障排除

### 程序无法启动
- 检查是否已有实例在运行
- 确保以管理员权限运行

### 代理无法工作
- 检查证书是否已正确安装（点击「安装证书」）
- 确认 hosts 文件已正确修改（`C:\Windows\System32\drivers\etc\hosts`）
- 查看日志输出了解详细错误信息
- 检查代理软件是否将目标域名设置为直连

### 客户端连接失败
- 确保客户端信任了代理 CA 证书
- 检查目标服务器地址是否正确
- 使用「测试连接」按钮验证后端服务器可达性

### 模型不在列表中
- 在「模型映射」中添加映射规则，源模型会自动注入到模型列表
- 确认映射规则中的源模型名称与客户端请求的名称一致

## 更新日志

### 2026-02-27

- 新增 Anthropic 入站请求处理：支持客户端直接以 Anthropic 协议（`/v1/messages`）发送请求，自动根据协议模式转发或转换
- 新增 Anthropic→OpenAI 协议转换：Anthropic 格式请求可自动转换为 OpenAI 格式发送到后端
- 新增 OpenAI→Anthropic 流式响应转换：将 OpenAI SSE 流式响应实时转换为 Anthropic SSE 格式返回客户端
- 新增 Anthropic 流式透传模式：Anthropic→Anthropic 场景下直接透传流式响应
- 新增 thinking/reasoning 内容支持：流式转换中正确处理 `thinking_delta` 和 `reasoning_content` 字段
- 新增路径归一化函数 `normalizeRequestPath`，统一处理 Gemini `/v1beta/openai/` 和 `/api/v1/` 路径前缀转换
- 新增目标服务器历史记录：目标服务器输入框改为下拉组合框，支持保存和选择历史地址，支持删除历史记录
- 新增透传请求头过滤：自动移除 `Accept-Encoding` 和响应中的 `Content-Encoding` 头，避免压缩编码问题
- 新增 `x-api-key` → `Authorization` 自动转换：透传请求中自动将 Anthropic 风格的认证头转换为 Bearer Token
- 改进模型列表格式检测：根据客户端类型（Anthropic/OpenAI）智能选择模型列表返回格式，而非仅依赖域名判断
- 改进 `convertGeminiToOpenAIModelFormat`：同时支持解析 Gemini 原生格式和 OpenAI 格式的模型列表，并注入映射模型
- 改进 OpenAI 直连模式错误响应：非 200 状态码时正确设置 `Content-Type: application/json`
- 改进 `convertStreamEvent`：`thinking` 类型的 `content_block_start` 不再生成多余的流式事件

### 2026-02-14

- 修复模型映射表显示乱序问题，改为按源模型名称排序
- 修复模型映射规则不生效的问题（支持自动去除 `provider/model` 前缀后匹配）
- 新增请求参数日志输出（model、stream、max_tokens）
- 新增映射模型自动注入到模型列表，支持 OpenAI、Anthropic、Gemini 三种格式
- 新增日志模式切换：GUI 实时显示 / 输出到本地日志文件
- 日志文件每次启动时自动清空，文件输出不限制内容长度
- UI 调整：「显示日志」复选框移至按钮栏，移除「最小化到托盘」按钮（改为窗口最小化时自动隐藏到托盘）
- UI 调整：隐藏日志时窗口自动缩小，显示日志时自动恢复
- 模型映射操作改为右键上下文菜单，支持列标题点击排序

## 许可证

MIT License

## 致谢

- [lxn/walk](https://github.com/lxn/walk) - Windows GUI 框架
- [go-winres](https://github.com/tc-hib/go-winres) - Windows 资源编译工具

# First

<div align="center">

**微信小程序安全调试框架**

基于 Frida + CDP 代理 · Windows / macOS 双平台 · GUI 与 CLI 双模式

**支持 MCP（Model Context Protocol）——让 Claude / Cursor / Copilot 直接操控小程序，实现 AI 驱动的自动化渗透测试**

</div>

---

## MCP 概述

First 将全部调试能力封装为 **20 个标准 MCP 工具**，AI Agent 可通过自然语言完成完整的小程序安全测试流程：枚举路由、提取凭证、Hook 网络请求、审计云函数、扫描敏感信息……无需手动编写脚本。

```
对这个小程序做渗透测试，先检查连接，然后枚举所有路由，
读取本地存储中的 token，再 Hook 所有 wx.request 请求。
```

---

## MCP 快速接入

### 第一步：安装 MCP 依赖

```bash
cd First
python3 -m venv .venv_mcp
source .venv_mcp/bin/activate   # Windows: .venv_mcp\Scripts\activate
pip install mcp websockets
```

### 第二步：启动 First 调试框架

```bash
# macOS（需要 sudo 以注入进程）
sudo .venv/bin/python gui.py

# Windows（以管理员身份运行）
python gui.py
```

打开微信 → 进入目标小程序 → 等待界面显示 **Frida 注入成功**。

### 第三步：在 AI 工具中配置 MCP Server

将以下内容加入你的 MCP 配置文件：

- **Claude Desktop**：`~/Library/Application Support/Claude/claude_desktop_config.json`
- **Cursor**：`.cursor/mcp.json`
- **VS Code Copilot**：`.vscode/mcp.json`

```json
{
  "mcpServers": {
    "miniapp-pentest": {
      "command": "/绝对路径/First/.venv_mcp/bin/python",
      "args": ["/绝对路径/First/mcp_server.py"],
      "env": {
        "PYTHONPATH": "/绝对路径/First",
        "FIRST_CDP_PORT": "62000"
      }
    }
  }
}
```

> 将 `/绝对路径/First` 替换为本地实际路径；Windows 使用反斜杠并注意 JSON 转义。

### 第四步：开始 AI 辅助测试

MCP Server 启动后，在 Claude / Cursor / Copilot 中用自然语言下指令即可。建议从 `check_connection` 开始确认连接状态。

---

## MCP 工具参考

### 连接与信息

| 工具 | 描述 |
|------|------|
| `check_connection` | 检查 First 调试框架运行状态与 CDP 连接，**每次测试前必须首先调用** |
| `get_miniapp_info` | 获取当前小程序 AppID、名称、版本号、SDK 版本、入口页面及完整页面列表 |
| `get_current_page` | 获取当前显示页面的路由、URL 参数及页面 `data` 状态 |
| `get_app_global_data` | 读取 `App.globalData`，通常包含登录状态、用户信息、全局配置等 |

### 路由与导航

| 工具 | 描述 |
|------|------|
| `get_all_routes` | 枚举小程序所有已注册页面路由，自动标注 tabBar 页面 |
| `navigate_to_route` | 跳转到指定路由（tabBar 自动使用 `switchTab`），可绕过前端页面鉴权 |

### JavaScript 执行

| 工具 | 描述 |
|------|------|
| `execute_js` | 在 AppService 上下文执行任意 JS，自动定位含有 `wx` 对象的 frame |
| `inject_hook_script` | 注入完整 JS Hook 脚本，可 Hook 任意函数、替换全局变量、绕过鉴权检查 |

### 本地存储与凭证

| 工具 | 描述 |
|------|------|
| `read_storage` | 读取本地存储中指定 key 的值（`wx.getStorageSync`） |
| `dump_all_storage` | 导出全部本地存储键值对，发现 token / sessionKey / openid 等敏感数据 |
| `get_user_credentials` | 从存储与 `globalData` 中自动提取 token、openid、session 等认证凭据 |

### 网络请求

| 工具 | 描述 |
|------|------|
| `start_network_capture` | 安装 `wx.request` Hook 开始捕获请求，页面跳转后自动检测并可重装 |
| `get_captured_requests` | 获取已捕获的请求列表，支持保留或清空记录 |
| `set_request_headers` | 同时在 CDP Network 层和 JS `wx.request` 层注入自定义 HTTP 头，确保全覆盖 |
| `replay_request` | 通过小程序上下文重放/构造 HTTP 请求，支持自定义方法、请求头和请求体 |

### 云函数审计

| 工具 | 描述 |
|------|------|
| `enable_cloud_function_hook` | 注入 Hook 监控所有 `wx.cloud.callFunction` 调用，记录函数名与参数 |
| `get_cloud_calls` | 获取已捕获的云函数调用记录（需先安装 Hook） |
| `call_cloud_function` | 直接调用指定云函数并自定义参数，测试鉴权缺失、越权、参数注入等漏洞 |

### 静态分析与解包

| 工具 | 描述 |
|------|------|
| `decompile_wxapkg` | 解密并解包 wxapkg 小程序包文件到 `output/` 目录 |
| `list_decompiled_apps` | 列出 `output/` 目录中已解包的小程序及 JS 文件统计 |
| `scan_sensitive_info` | 扫描已解包源码，检测 API Key、JWT、Secret、IP、OSS 配置、手机号、身份证等敏感信息 |
| `find_api_endpoints` | 从 JS 源码中提取所有 HTTP(S) URL、API 路径和配置变量 |

### 鉴权绕过

| 工具 | 描述 |
|------|------|
| `bypass_auth_check` | 尝试常见鉴权绕过手法：`token_spoof`（查找并伪造 token）、`admin_role`（提权）、`skip_login`（跳过登录态检查）、`dump_login_logic`（仅读取鉴权变量不修改） |

---

## 典型测试流程

```
1. check_connection          — 确认连接
2. get_miniapp_info          — 了解目标基本信息
3. get_all_routes            — 枚举全部页面路由
4. dump_all_storage          — 提取本地存储凭证
5. get_user_credentials      — 聚合认证信息
6. start_network_capture     — 安装抓包 Hook
7. navigate_to_route         — 遍历敏感页面触发请求
8. get_captured_requests     — 获取捕获结果
9. replay_request            — 重放/篡改关键请求
10. enable_cloud_function_hook — 监控云函数
11. decompile_wxapkg          — 解包小程序源码
12. scan_sensitive_info       — 审计源码敏感信息
```

---

## 截图预览

### 主界面

![主界面](https://s1.galgame.fun/imgb/u0/20260408_69d655f49ca7e.png)

### 路由导航

![路由导航](https://s1.galgame.fun/imgb/u0/20260408_69d6560ca1a39.png)

### 云函数分析

![云函数分析](https://s1.galgame.fun/imgb/u0/20260402_69ce527ca5480.png)

### 调试开关（JSRPC / wx.cloud 调用）

![调试开关](https://s1.galgame.fun/imgb/u0/20260408_69d6564195009.png)

### 敏感信息提取

![敏感信息提取-1](https://s1.galgame.fun/imgb/u55/20260416_69e0be0e1c1d7.png)

<img src="https://s1.galgame.fun/imgb/u55/20260416_69e0be0c38e39.png" alt="敏感信息提取-2" />

![敏感信息提取-3](https://s1.galgame.fun/imgb/u55/20260416_69e0be0c70d46.png)

---

## 功能特性

- Frida 动态注入微信客户端，转发小程序调试协议
- CDP 代理桥接，Chrome DevTools 直连调试
- 路由枚举、分类与一键跳转
- 云函数调用监控与参数分析（动态 Hook + 静态扫描）
- UserScript 自动注入（支持 URL 匹配、run-at 时机控制）
- wxapkg 解密解包 + 敏感信息扫描（IP / 密钥 / 云存储 / JWT 等）
- 深色 / 浅色主题切换
- GUI（PySide6）与 CLI 双模式

---

## 环境要求

| 依赖 | 版本 |
|------|------|
| Python | >= 3.10 |
| frida | >= 17.0.0 |
| websockets | >= 12.0 |
| protobuf | >= 4.0.0 |
| PySide6 | >= 6.5.0 |
| pycryptodome | 最新版 |

```bash
pip install -r requirements.txt
```

---

## 支持的微信版本

### Windows

- WMPF 版本：11581, 11633, 13331, 13341, 13487, 13639, 13655, 13871, 13909, 14161, 14199, 14315, 16133, 16203, 16389, 16467, 16771, 16815, 16965, 17037, 17071, 17127, 18055, 18151, 18787, 18891, 18955, 19027, 19201
- 推荐微信版本：**4.1.0.30**
- 下载地址：[weixin/4.1.0.30](https://github.com/vs-olitus/wx-version/releases/tag/4.1.0.30)

### macOS

- WMPF 版本：18152, 18788
- 推荐微信版本：**4.1.7.30**
- 下载地址：[weixin/4.1.7.30](https://github.com/vs-olitus/wx-version/releases/tag/4.1.7.30)

---

## 快速开始

### Windows

**一键启动：** 双击 `启动.bat`，首次运行会自动安装依赖。

**手动启动：**

```bash
python gui.py
```

### macOS

**一键启动：** 终端执行 `./启动.sh`，首次运行会自动安装依赖。

**手动启动：**

```bash
python3 gui.py
```

启动后在主界面点击 **启动调试**，然后再打开小程序即可（请勿在启动调试前打开小程序）。

### CLI 模式

```bash
# 默认端口启动
python main.py

# 自定义端口
python main.py --cdp-port 62000

# 开启详细日志
python main.py --debug-main --debug-frida
```

### 连接 Chrome DevTools

```
devtools://devtools/bundled/inspector.html?ws=127.0.0.1:62000
```

---

## 服务号调试操作

1. 打开一个小程序页面作为占位（保持不关闭）
2. 访问需要调试的服务号内容（如 H5 网页）

   ![PixPin_2026-05-04_22-48-42](https://s1.galgame.fun/imgb/u55/20260504_69f8b299a7d85.png)

3. 在工具栏「服务」目标列表中找到目标网页，双击后切换至调试视图即可开始调试

   ![PixPin_2026-05-04_22-51-14](https://s1.galgame.fun/imgb/u55/20260504_69f8b299a7d94.png)
   ![PixPin_2026-05-04_22-51-39](https://s1.galgame.fun/imgb/u55/20260504_69f8b299a804b.png)

---

## macOS 注意事项

如果 Frida 注入报错，需要解除系统对进程附加的限制，任选其一：

**方案一：关闭 SIP（系统完整性保护）**

> 参考教程：[macOS SIP 开启关闭教程](https://cloud.tencent.com/developer/article/1496058)

**方案二：强制重签名 WeChat**

```bash
sudo codesign --force --deep --sign - /Applications/WeChat.app
```

---

## 参数说明

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--debug-port` | `9421` | 远程调试服务端口 |
| `--cdp-port` | `62000` | CDP 代理监听端口 |
| `--debug-main` | 关闭 | 输出主进程调试日志 |
| `--debug-frida` | 关闭 | 输出 Frida 客户端日志 |
| `--scripts-dir` | `./userscripts` | UserScript 目录路径 |
| `--script` | — | 指定单个 .js 文件注入（可多次使用） |

---

## UserScript 注入

将 `.js` 脚本放入 `userscripts/` 目录，启动时自动加载并注入。也可手动指定：

```bash
python main.py --script ./my_hook.js --script ./another.js
```

---

## 常见问题

**Q: Frida 已连接，但小程序端显示未连接或无法断点调试？**

1. 彻底卸载微信并重启电脑（重要聊天记录请提前备份）
2. 删除 `C:\Users\用户名\AppData\Roaming\Tencent\xwechat\XPlugin\Plugins\RadiumWMPF` 下所有数字命名的文件夹
3. 再次重启后安装微信 4.1.0.30 版本
4. 检查上述路径，确认文件夹编号为 `16389`

---

## 参考项目

- [evi0s/WMPFDebugger](https://github.com/evi0s/WMPFDebugger)
- [0xsdeo/HeartK](https://github.com/0xsdeo/HeartK)
- [残笑/FindSomething](https://github.com/momosecurity/FindSomething)
- [进击的HACK / JSRPC 与调用 wx.cloud](https://mp.weixin.qq.com/s/hTlekrCPiMJCvsHYx7CAxw)
- [linguo2625469/WMPFDebugger-mac](https://github.com/linguo2625469/WMPFDebugger-mac)

---

## 致谢

感谢 **0xsdeo** 师傅的大力支持与思路提供。

---

## 交流群

群满 200 人后需要手动邀请，请加我拉群：

![微信二维码](https://s1.galgame.fun/imgb/u55/20260413_69dcaf1310fc4.jpg)

---

## 免责声明

本工具仅供安全研究与学习使用，请勿用于未授权的目标，使用者须自行承担相关法律责任。

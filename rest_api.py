"""
rest_api.py — 将 First MCP 工具暴露为 REST API
容器里的 AI Agent 可以通过 curl 直接调用

启动方式:
    .venv_mcp/bin/python rest_api.py --port 7890

容器里调用示例:
    curl http://127.0.0.1:7890/api/check_connection
    curl http://127.0.0.1:7890/api/dump_all_storage
    curl -X POST http://127.0.0.1:7890/api/execute_js -d '{"expression":"wx.getAccountInfoSync()"}'
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# 确保能 import mcp_server 里的函数
sys.path.insert(0, str(Path(__file__).parent))

import mcp_server

try:
    from aiohttp import web
except ImportError:
    print("需要安装 aiohttp: pip install aiohttp")
    sys.exit(1)

# 把所有 mcp.tool 注册的函数收集起来
TOOLS: dict[str, callable] = {}

def _collect_tools():
    """从 mcp_server 模块中收集所有被 @mcp.tool() 装饰的异步函数"""
    import inspect
    # FastMCP 会把工具注册在 mcp._tool_manager._tools 中
    # 但最简单的方式是：直接从模块中找所有异步函数（排除下划线开头的内部函数）
    for name, obj in inspect.getmembers(mcp_server):
        if (inspect.iscoroutinefunction(obj)
            and not name.startswith('_')
            and name != 'main'):
            TOOLS[name] = obj


async def handle_list(request):
    """GET /api — 列出所有可用工具"""
    tool_list = []
    for name, fn in TOOLS.items():
        doc = (fn.__doc__ or "").strip().split("\n")[0]
        tool_list.append({"name": name, "description": doc})
    return web.json_response({"tools": tool_list})


async def handle_tool(request):
    """GET/POST /api/<tool_name> — 调用指定工具"""
    tool_name = request.match_info["name"]
    fn = TOOLS.get(tool_name)
    if not fn:
        return web.json_response(
            {"error": f"unknown tool: {tool_name}", "available": list(TOOLS.keys())},
            status=404,
        )

    # 解析参数
    params = {}
    if request.method == "POST":
        try:
            body = await request.text()
            if body.strip():
                params = json.loads(body)
        except json.JSONDecodeError:
            return web.json_response({"error": "invalid JSON body"}, status=400)
    else:
        params = dict(request.query)

    # 调用工具
    try:
        import inspect
        sig = inspect.signature(fn)
        # 过滤掉函数不接受的参数
        valid_params = {k: v for k, v in params.items() if k in sig.parameters}
        result = await fn(**valid_params)
        # 尝试解析为 JSON
        try:
            parsed = json.loads(result) if isinstance(result, str) else result
            return web.json_response({"ok": True, "result": parsed})
        except (json.JSONDecodeError, TypeError):
            return web.json_response({"ok": True, "result": result})
    except Exception as e:
        return web.json_response({"ok": False, "error": str(e)}, status=500)


def create_app():
    app = web.Application()
    app.router.add_get("/api", handle_list)
    app.router.add_get("/api/{name}", handle_tool)
    app.router.add_post("/api/{name}", handle_tool)
    return app


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="First REST API wrapper")
    parser.add_argument("--port", type=int, default=7890, help="监听端口 (默认 7890)")
    parser.add_argument("--cdp-port", type=int, default=int(os.getenv("FIRST_CDP_PORT", "62000")),
                        help="First CDP 代理端口")
    args = parser.parse_args()

    # 设置 CDP 端口
    mcp_server.CDP_PORT = args.cdp_port
    mcp_server.CDP_URL = f"ws://127.0.0.1:{args.cdp_port}"

    _collect_tools()
    print(f"First REST API 启动在 http://0.0.0.0:{args.port}")
    print(f"CDP 目标: ws://127.0.0.1:{args.cdp_port}")
    print(f"已注册工具: {len(TOOLS)} 个 — {', '.join(sorted(TOOLS.keys()))}")
    print(f"\n容器调用示例:")
    print(f"  curl http://127.0.0.1:{args.port}/api/check_connection")
    print(f"  curl http://127.0.0.1:{args.port}/api/dump_all_storage")

    web.run_app(create_app(), host="0.0.0.0", port=args.port, print=None)

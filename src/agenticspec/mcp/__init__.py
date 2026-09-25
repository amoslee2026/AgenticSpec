"""M13 AgenticSpec MCP server（GigaPie/opencode 等 headless agent 接入；stdio 传输）。"""

from agenticspec.mcp.server import build_server, run_stdio

__all__ = ["build_server", "run_stdio"]

"""AgenticSpec MCP server（M13；GigaPie headless bot / 内网 agent 接入）。

**薄壳**：每个工具调用 = 一次对 AgenticSpec REST API 的 **SSH 签名请求**（复用 M11
:class:`~agenticspec.cli.SigningClient`），身份 = 本进程私钥归属账号（``AGENTICSPEC_SSH_KEY``
→ ``~/.ssh/id_ed25519`` → ``~/.ssh/id_rsa``）。读写权限由服务端按该账号的角色 + grant
门控（ADR-007 §5 / M10），与「agent 身份 = 启动它的人类用户」（ADR-007 B2）同一模型：
bot 想独立身份时，给 bot 专属密钥并注册账号、启动时 ``AGENTICSPEC_SSH_KEY`` 指向它即可。

**用途**：供 GigaPie/opencode/pi 等 harness 以 stdio command 方式挂载；base URL
走 ``AGENTICSPEC_API_URL``（缺省 http://127.0.0.1:8787）。
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from agenticspec.auth.signing import default_key_path
from agenticspec.cli import CliError, SigningClient
from agenticspec.observability.logger import get_logger

log = get_logger("m13.mcp")


def _text_error(exc: CliError) -> RuntimeError:
    """CliError（含可操作指引）→ MCP 工具错误文案。"""
    hint = "\n".join(exc.hint) if isinstance(exc.hint, (list, tuple)) else (exc.hint or "")
    return RuntimeError(f"{exc.message}\n{hint}" if hint else exc.message)


def build_server(client: SigningClient | None = None) -> MCPServer:
    """装配 MCP server；``client`` 供测试注入（缺省用真实签名客户端）。"""
    svc = client or SigningClient()
    server = MCPServer("agenticspec")

    def invoke(method: str, path: str, **kw: Any) -> Any:
        try:
            return svc.json(method, path, **kw)
        except CliError as exc:
            raise _text_error(exc) from exc

    @server.tool()
    def docs_list(status: str | None = None) -> list[dict]:
        """列出文档；可选 status 过滤（如 draft|active|archived，省略 → 全部）。"""
        return invoke("GET", "/api/v1/docs", params={"status": status} if status else None)

    @server.tool()
    def docs_get(doc_id: str) -> dict:
        """单个文档详情（含 meta/frontmatter）。"""
        return invoke("GET", f"/api/v1/docs/{doc_id}")

    @server.tool()
    def docs_sections(doc_id: str) -> list[dict]:
        """文档章节树（anchor/title/level/childCount…）。"""
        return invoke("GET", f"/api/v1/docs/{doc_id}/sections")

    @server.tool()
    def docs_render(doc_id: str, section: str | None = None) -> dict:
        """渲染文档（section 给 anchor 或 node_id 则只渲染该章节）；返回 markdown 文本。"""
        return invoke(
            "GET",
            f"/api/v1/docs/{doc_id}/render",
            params={"section": section} if section else None,
        )

    @server.tool()
    def nodes_list(doc_id: str) -> list[dict]:
        """列出文档全部节点（agent_api 口径：树序 + 软删过滤）。"""
        return invoke("GET", f"/api/v1/docs/{doc_id}/nodes")

    @server.tool()
    def nodes_get(node_id: str, doc_id: str | None = None) -> dict:
        """节点点查（含 version/status）；doc_id 给定则点查裁到单分区。"""
        return invoke(
            "GET",
            f"/api/v1/nodes/{node_id}",
            params={"doc_id": doc_id} if doc_id else None,
        )

    @server.tool()
    def nodes_write(body: dict[str, Any]) -> dict:
        """写入节点（新建或按 expectedVersion 更新）。body 含：
        docId、nodeId(缺省=新建)、atomType、content、meta、refs、expectedVersion(乐观锁)。
        权限=本进程身份的 write 角色 + 该 doc 的 grant；422 返回违规明细可自修复重试。"""
        return invoke("POST", "/api/v1/nodes", body=body)

    @server.tool()
    def nodes_delete(node_id: str, expected_version: int) -> None:
        """软删节点（须给乐观锁版本 nodes.version，不匹配 → 409）。"""
        return invoke(
            "DELETE",
            f"/api/v1/nodes/{node_id}",
            params={"expected_version": expected_version},
        )

    @server.tool()
    def refs_write(body: dict[str, Any]) -> dict:
        """新增引用边：src(节点id)、dstDoc、dstNode(可空)、kind(取值域见 schema)。"""
        return invoke("POST", "/api/v1/refs", body=body)

    @server.tool()
    def refs_remove(body: dict[str, Any]) -> None:
        """删除引用边（同 refs_write 字段）。"""
        return invoke("DELETE", "/api/v1/refs", body=body)

    return server


def run_stdio() -> None:
    """stdio 模式主循环（Ctrl-C 退出）。"""
    # private_key 在首个工具调用时按环境查找；此处预热并记录身份便于排障
    identity = "（登录机）"
    if (kp := default_key_path()).exists():
        identity = str(kp)
    log.info("mcp server start", transport="stdio", key_path=identity)
    build_server().run()

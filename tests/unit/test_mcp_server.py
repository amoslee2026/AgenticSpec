"""M13 MCP server（unit）：工具调用 → 签名 REST 请求 的映射（MockTransport 注入，不触网）。

覆盖：10 个工具的 method/path/params/body 映射、每请求携带四个签名头、
HTTP 401/403 → 工具错误（ToolError → 客户端 isError 结果 + 指引透传）。
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from agenticspec.cli import SigningClient
from agenticspec.mcp.server import build_server
from mcp.server.mcpserver.exceptions import ToolError


def _keypair(tmp_path: Path) -> Path:
    """生成一把 OpenSSH 格式测试私钥 + 同名 .pub（load_private_key 只认 OpenSSH 格式）。"""
    key = ed25519.Ed25519PrivateKey.generate()
    priv = tmp_path / "testkey"
    priv.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    (tmp_path / "testkey.pub").write_text(f"ssh-ed25519 {pub.decode()} agenticspec-test\n")
    return priv


def _server(
    key: Path,
    history: list[tuple[str, httpx.Request]],
    responses: dict[str, object] | None = None,
    error: tuple[int, object] | None = None,
):
    """``responses``: {url_path_prefix: json}；``error``: (status, json) 优先；DELETE → 204。"""
    responses = responses or {}

    def handler(request: httpx.Request) -> httpx.Response:
        history.append((request.method, request))
        if error is not None:
            return httpx.Response(error[0], json=error[1])
        if request.method == "DELETE":
            return httpx.Response(204)
        for prefix, payload in responses.items():
            if request.url.path.startswith(prefix):
                return httpx.Response(200, json=payload)
        return httpx.Response(200, json={})

    client = SigningClient(
        key_path=key,
        base_url="http://test.local",
        transport=httpx.MockTransport(handler),
    )
    return build_server(client)


def _text(result: object) -> str:
    return result.content[0].text


@pytest.fixture
def key(tmp_path: Path) -> Path:
    return _keypair(tmp_path)


def _assert_signed(headers: httpx.Headers) -> None:
    assert headers.get("X-SSH-Key-Id", "").startswith("SHA256:")
    assert headers.get("X-SSH-Signature")
    assert headers.get("X-Timestamp")
    assert headers.get("X-Nonce")


async def test_docs_list_maps_get_and_signs(key: Path) -> None:
    history: list[tuple[str, httpx.Request]] = []
    srv = _server(key, history, responses={"/api/v1/docs": [{"docId": "SPEC-X"}]})
    result = await srv.call_tool("docs_list", {})
    assert result.is_error is False
    assert '"SPEC-X"' in _text(result)
    method, req = history[0]
    assert method == "GET"
    assert req.url.path == "/api/v1/docs"
    _assert_signed(req.headers)


async def test_docs_list_status_filter(key: Path) -> None:
    history: list[tuple[str, httpx.Request]] = []
    srv = _server(key, history, responses={"/api/v1/docs": []})
    await srv.call_tool("docs_list", {"status": "active"})
    assert history[0][1].url.params["status"] == "active"


async def test_docs_get_maps_path(key: Path) -> None:
    history: list[tuple[str, httpx.Request]] = []
    srv = _server(key, history, responses={"/api/v1/docs/SPEC-X": {"docId": "SPEC-X"}})
    await srv.call_tool("docs_get", {"doc_id": "SPEC-X"})
    assert (history[0][0], history[0][1].url.path) == ("GET", "/api/v1/docs/SPEC-X")


async def test_docs_sections_maps_path(key: Path) -> None:
    history: list[tuple[str, httpx.Request]] = []
    srv = _server(key, history, responses={"/api/v1/docs/SPEC-X/sections": []})
    await srv.call_tool("docs_sections", {"doc_id": "SPEC-X"})
    assert (history[0][0], history[0][1].url.path) == ("GET", "/api/v1/docs/SPEC-X/sections")


async def test_docs_render_optional_section(key: Path) -> None:
    history: list[tuple[str, httpx.Request]] = []
    srv = _server(key, history, responses={"/api/v1/docs/SPEC-X/render": {"markdown": "x"}})
    await srv.call_tool("docs_render", {"doc_id": "SPEC-X", "section": "1.2"})
    req = history[0][1]
    assert req.url.path == "/api/v1/docs/SPEC-X/render"
    assert req.url.params["section"] == "1.2"


async def test_nodes_list_and_get(key: Path) -> None:
    history: list[tuple[str, httpx.Request]] = []
    srv = _server(
        key,
        history,
        responses={
            "/api/v1/docs/SPEC-X/nodes": [],
            "/api/v1/nodes/01a0aa40-1990-7dce-9368-d9bfe8d6d045": {"nodeId": "x"},
        },
    )
    await srv.call_tool("nodes_list", {"doc_id": "SPEC-X"})
    assert history[0][1].url.path == "/api/v1/docs/SPEC-X/nodes"
    await srv.call_tool("nodes_get", {"node_id": "01a0aa40-1990-7dce-9368-d9bfe8d6d045", "doc_id": "SPEC-X"})
    req = history[1][1]
    assert req.url.path == "/api/v1/nodes/01a0aa40-1990-7dce-9368-d9bfe8d6d045"
    assert req.url.params["doc_id"] == "SPEC-X"


async def test_nodes_write_posts_body(key: Path) -> None:
    history: list[tuple[str, httpx.Request]] = []
    srv = _server(key, history, responses={"/api/v1/nodes": {"nodeId": "x"}})
    body = {"docId": "SPEC-X", "atomType": "prose", "content": {"text": "hi"}, "expectedVersion": 3}
    await srv.call_tool("nodes_write", {"body": body})
    method, req = history[0]
    assert method == "POST"
    assert req.url.path == "/api/v1/nodes"
    import json

    assert json.loads(req.content)["expectedVersion"] == 3


async def test_nodes_delete_requires_expected_version(key: Path) -> None:
    history: list[tuple[str, httpx.Request]] = []
    srv = _server(key, history)
    await srv.call_tool("nodes_delete", {"node_id": "01a0aa40-1990-7dce-9368-d9bfe8d6d045", "expected_version": 7})
    method, req = history[0]
    assert method == "DELETE"
    assert req.url.path == "/api/v1/nodes/01a0aa40-1990-7dce-9368-d9bfe8d6d045"
    assert req.url.params["expected_version"] == "7"


async def test_refs_write_and_remove(key: Path) -> None:
    history: list[tuple[str, httpx.Request]] = []
    srv = _server(key, history, responses={"/api/v1/refs": {}})
    ref = {"src": "01a0aa40-1990-7dce-9368-d9bfe8d6d045", "dstDoc": "SPEC-Y", "kind": "references"}
    await srv.call_tool("refs_write", {"body": ref})
    assert (history[0][0], history[0][1].url.path) == ("POST", "/api/v1/refs")
    await srv.call_tool("refs_remove", {"body": ref})
    assert (history[1][0], history[1][1].url.path) == ("DELETE", "/api/v1/refs")


async def test_forbidden_error_surfaces_readable_result(key: Path) -> None:
    history: list[tuple[str, httpx.Request]] = []
    srv = _server(
        key,
        history,
        error=(403, {"detail": {"code": "AUTH_REJECTED", "message": "公钥未注册或其属主已禁用（S8）"}}),
    )
    result = await srv.call_tool("docs_list", {})
    assert result.is_error is True
    assert "403" in _text(result)

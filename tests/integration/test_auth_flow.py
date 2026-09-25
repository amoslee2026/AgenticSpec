"""M10 集成测试（**真实 PG**；REQ-M10-F01..F05 的 11 项安全验收 S1–S15）。

覆盖：自举（幂等 + 救援 + fail-closed）、agent 请求签名（S2 query/body 篡改、S3 时间窗与
重放、S7 失败不写 nonce、S4 豁免清单、S11 与真实 ``ssh-keygen -Y sign`` 的端到端互操作）、
会话登录（S13 token 哈希、S8 禁用即失效、S15 清理、S6 Cookie 标志）、RBAC（S5 角色上限 +
grant 收窄、**授予与判定两处均拒**）、用户/密钥管理（S9 自身与最后管理员）、审计
（S1 ``entity='auth'``、S10 ``actor='anonymous'`` + ``claimed_*``）。

HTTP 面用真实 FastAPI 应用（``include_router`` + ``require_auth`` 依赖），经
``httpx.ASGITransport`` 直连，不启进程。
"""

from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from fastapi import Depends, FastAPI, Request
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from agenticspec.auth import bootstrap, middleware, sessions, signing, sshsig
from agenticspec.auth import users as auth_users
from agenticspec.auth.errors import BootstrapError
from agenticspec.auth.router import router as auth_router
from agenticspec.model import DocTarget, DocTypeTarget, WriteContext, new_uuid7
from agenticspec.store import (
    ConflictError,
    Database,
    ForbiddenError,
    NotFoundError,
    ValidationError,
)

pytestmark = pytest.mark.integration

SSH_KEYGEN = shutil.which("ssh-keygen")
needs_ssh_keygen = pytest.mark.skipif(SSH_KEYGEN is None, reason="需要本机 ssh-keygen")

SYSTEM_ACTOR = "system"


# ------------------------------------------------------------------------ 夹具


@pytest.fixture(scope="module")
def key_material(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """密码学库生成的两把私钥（不需要外部命令；CLI 互操作用例另用 ssh-keygen 现生成）。"""
    directory = tmp_path_factory.mktemp("authkeys")
    paths: dict[str, Path] = {}
    for name, key in (
        ("admin_ed25519", ed25519.Ed25519PrivateKey.generate()),
        ("editor_ed25519", ed25519.Ed25519PrivateKey.generate()),
        ("outsider_ed25519", ed25519.Ed25519PrivateKey.generate()),
        ("rsa_3072", rsa.generate_private_key(public_exponent=65537, key_size=3072)),
    ):
        target = directory / name
        target.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.OpenSSH,
                serialization.NoEncryption(),
            )
        )
        target.with_suffix(".pub").write_text(signing.public_key_line(key) + "\n")
        paths[name] = target
    return paths


@pytest.fixture
def admin_pub_path(key_material: dict[str, Path], tmp_path: Path, monkeypatch) -> Path:
    """``ADMIN_SSH_PUBKEY_FILE`` 指向 admin 公钥（自举入口）。"""
    target = tmp_path / "admin.pub"
    target.write_text(key_material["admin_ed25519"].with_suffix(".pub").read_text())
    monkeypatch.setenv("ADMIN_SSH_PUBKEY_FILE", str(target))
    monkeypatch.setenv("AUTH_RATE_LIMIT_PER_MIN", "1000")
    return target


@pytest.fixture(autouse=True)
def _reset_auth_windows() -> None:
    sessions.reset_rate_limits()
    auth_users.reset_failure_aggregates()


@pytest.fixture(autouse=True)
async def _clean_auth_tables(database: Database) -> AsyncIterator[None]:
    """每个用例从空鉴权状态开始（``users`` 级联清 keys/grants/sessions）。

    ``grants.granted_by`` 无级联动作，故先置空再删用户（与 ``users.delete_user`` 同口径）。
    """
    async def _wipe() -> None:
        async with database.transaction() as session:
            await session.execute(text("UPDATE grants SET granted_by = NULL"))
            await session.execute(text("DELETE FROM users"))
            await session.execute(text("DELETE FROM nonces"))

    await _wipe()
    yield
    await _wipe()


@pytest.fixture
def app(database: Database) -> FastAPI:
    """最小 FastAPI 应用：M10 依赖项 + 一个受保护端点（M06/M07 的装配形态）。"""
    application = FastAPI()
    application.state.auth_db = database
    application.include_router(auth_router)

    @application.get("/healthz")
    async def healthz() -> dict[str, str]:  # S4 豁免
        return {"status": "ok"}

    @application.get("/")
    async def index() -> dict[str, bool]:  # 登录页（S4 豁免）
        return {"login": True}

    @application.get("/api/v1/docs")
    async def list_docs(ctx: middleware.AuthContext = Depends(middleware.require_auth)) -> dict:
        return {"actor": ctx.actor, "source": ctx.source, "username": ctx.user.username}

    @application.get("/api/v1/docs/{doc_id}")
    async def get_doc(
        doc_id: str, ctx: middleware.AuthContext = Depends(middleware.require_auth)
    ) -> dict:
        return {"docId": doc_id, "actor": ctx.actor}

    @application.post("/api/v1/docs")
    async def create_doc(
        payload: dict, ctx: middleware.AuthContext = Depends(middleware.require_permission("write"))
    ) -> dict:
        return {"actor": ctx.actor, "received": payload}

    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as http_client:
        yield http_client


async def _scalar(database: Database, sql: str, **params: object) -> object:
    async with database.session() as session:
        return (await session.execute(text(sql), params)).scalar_one()


async def _rows(database: Database, sql: str, **params: object) -> list[tuple]:
    async with database.session() as session:
        return list((await session.execute(text(sql), params)).all())


# -------------------------------------------------------------------- 自举（F05）


async def test_bootstrap_creates_admin_and_is_idempotent(
    database: Database, admin_pub_path: Path, key_material: dict[str, Path]
) -> None:
    admin = await bootstrap.bootstrap_admin(db=database)
    assert admin.role == "admin" and admin.status == "active"
    assert admin.username == "admin"

    keys = await auth_users.list_ssh_keys(admin.user_id, db=database)
    assert len(keys) == 1
    assert keys[0].key_type == "ssh-ed25519"
    assert keys[0].fingerprint == signing.fingerprint(
        key_material["admin_ed25519"].with_suffix(".pub").read_text()
    )

    # 幂等：第二次仍是同一 admin，不重复建号/建键
    again = await bootstrap.bootstrap_admin(db=database)
    assert again.user_id == admin.user_id
    assert len(await auth_users.list_ssh_keys(admin.user_id, db=database)) == 1
    assert len(await auth_users.list_users(db=database)) == 1

    # 「以 DB 为准」：键文件换成别的公钥也不改写现有 admin
    admin_pub_path.write_text(key_material["outsider_ed25519"].with_suffix(".pub").read_text())
    unchanged = await bootstrap.bootstrap_admin(db=database)
    assert unchanged.user_id == admin.user_id
    assert len(await auth_users.list_ssh_keys(admin.user_id, db=database)) == 1


async def test_bootstrap_rescues_when_no_active_admin(
    database: Database, admin_pub_path: Path
) -> None:
    admin = await bootstrap.bootstrap_admin(db=database)
    async with database.transaction() as session:  # 模拟「无 active admin」（S9 救援场景）
        await session.execute(
            text("UPDATE users SET status = 'disabled' WHERE user_id = :uid"), {"uid": admin.user_id}
        )
    assert await bootstrap.has_active_admin(db=database) is False

    rescued = await bootstrap.bootstrap_admin(db=database)
    assert rescued.user_id == admin.user_id
    assert rescued.status == "active" and rescued.role == "admin"
    assert await bootstrap.has_active_admin(db=database) is True


async def test_bootstrap_fails_closed_without_key_file(
    database: Database, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("ADMIN_SSH_PUBKEY_FILE", str(tmp_path / "absent.pub"))
    with pytest.raises(BootstrapError) as excinfo:
        await bootstrap.bootstrap_admin(db=database)
    assert "auth bootstrap" in str(excinfo.value)

    empty = tmp_path / "empty.pub"
    empty.write_text("   \n")
    with pytest.raises(BootstrapError):
        await bootstrap.bootstrap_admin(empty, db=database)


async def test_no_users_means_all_requests_401_with_bootstrap_hint(
    client: AsyncClient, database: Database
) -> None:
    for path in ("/api/v1/docs", "/api/v1/auth/me"):
        response = await client.get(path)
        assert response.status_code == 401, path
        assert "auth bootstrap" in response.json()["detail"]["message"]
    # 无 active admin 时的 401 也落审计（S1/S10）
    events = await _rows(
        database,
        "SELECT actor, payload FROM events WHERE entity = 'auth' AND op = 'fail'",
    )
    assert events and all(actor == "anonymous" for actor, _ in events)


# ------------------------------------------------------- agent 签名路径（F01）


async def _make_user(database: Database, username: str, role: str, key_path: Path):
    user = await auth_users.create_user(username, role, actor=SYSTEM_ACTOR, db=database)
    key = await auth_users.add_ssh_key(
        user.user_id, key_path.with_suffix(".pub").read_text(), actor=SYSTEM_ACTOR, db=database
    )
    return user, key


async def test_signed_request_authenticates_and_attributes_actor(
    client: AsyncClient, database: Database, key_material: dict[str, Path]
) -> None:
    user, _ = await _make_user(database, "alice", "editor", key_material["editor_ed25519"])
    key = signing.load_private_key(key_material["editor_ed25519"])

    headers = signing.sign_request_headers(key, "GET", "/api/v1/docs")
    response = await client.get("/api/v1/docs", headers=headers)
    assert response.status_code == 200, response.text
    assert response.json() == {"actor": str(user.user_id), "source": "agent", "username": "alice"}


async def test_query_tampering_is_rejected(
    client: AsyncClient, database: Database, key_material: dict[str, Path]
) -> None:
    """**S2**：query 原样参与签名，改任一参数即 401。"""
    await _make_user(database, "alice", "editor", key_material["editor_ed25519"])
    key = signing.load_private_key(key_material["editor_ed25519"])
    headers = signing.sign_request_headers(key, "GET", "/api/v1/docs?expected_version=3")

    ok = await client.get("/api/v1/docs?expected_version=3", headers=headers)
    assert ok.status_code == 200
    # nonce 已消费，换一个 nonce 重签后再篡改 query
    headers = signing.sign_request_headers(key, "GET", "/api/v1/docs?expected_version=3")
    tampered = await client.get("/api/v1/docs?expected_version=4", headers=headers)
    assert tampered.status_code == 401
    assert tampered.json()["detail"]["reason"] == "bad_signature"


async def test_body_and_path_tampering_is_rejected(
    client: AsyncClient, database: Database, key_material: dict[str, Path]
) -> None:
    await _make_user(database, "alice", "editor", key_material["editor_ed25519"])
    key = signing.load_private_key(key_material["editor_ed25519"])

    body = b'{"title":"A"}'
    # Content-Type 不参与签名载荷（S2 只绑 METHOD/RAW_PATH/body 摘要/TS/nonce）
    json_headers = {"Content-Type": "application/json"}
    headers = signing.sign_request_headers(key, "POST", "/api/v1/docs", body)
    assert (
        await client.post("/api/v1/docs", content=body, headers={**headers, **json_headers})
    ).status_code == 200

    headers = signing.sign_request_headers(key, "POST", "/api/v1/docs", b'{"title":"B"}')
    assert (
        await client.post("/api/v1/docs", content=b'{"title":"A"}', headers={**headers, **json_headers})
    ).status_code == 401

    tampered_path = signing.sign_request_headers(key, "GET", "/api/v1/docs/SPEC-A")
    response = await client.get("/api/v1/docs/SPEC-B", headers=tampered_path)
    assert response.status_code == 401


async def test_signature_covers_percent_encoded_target(
    client: AsyncClient, database: Database, key_material: dict[str, Path]
) -> None:
    """**AUD-2 回归**：RAW_PATH 取 ASGI ``raw_path``（**未解码**的原样字节，S2 字面）。

    客户端契约因此是「签请求行里那个目标串」：签编码形态 → 200；先 ``unquote`` 再签 → 401
    （服务端不会替客户端解码，也不存在「签解码形态」这条隐式耦合）。
    """
    await _make_user(database, "alice", "editor", key_material["editor_ed25519"])
    key = signing.load_private_key(key_material["editor_ed25519"])

    encoded = signing.sign_request_headers(key, "GET", "/api/v1/docs/SPEC%20A")
    response = await client.get("/api/v1/docs/SPEC%20A", headers=encoded)
    assert response.status_code == 200, response.text
    assert response.json()["docId"] == "SPEC A"  # 路由仍按解码路径匹配（FastAPI 语义）

    decoded = signing.sign_request_headers(key, "GET", "/api/v1/docs/SPEC A")
    response = await client.get("/api/v1/docs/SPEC%20A", headers=decoded)
    assert response.status_code == 401
    assert response.json()["detail"]["reason"] == "bad_signature"


async def test_missing_raw_path_scope_falls_back_with_warning(monkeypatch) -> None:
    """ASGI ``raw_path`` 缺失（规范允许省略）→ 回落解码路径，且只告警一次。"""
    monkeypatch.setattr(middleware, "_MISSING_RAW_PATH_WARNED", False, raising=False)
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/docs/SPEC A",  # ASGI path 已解码
        "query_string": b"limit=1",
        "headers": [],
        "client": ("10.0.0.9", 1),
    }
    assert middleware.raw_path(Request(scope)) == "/api/v1/docs/SPEC A?limit=1"
    scope["raw_path"] = b"/api/v1/docs/SPEC%20A"  # 请求行原样字节
    assert middleware.raw_path(Request(scope)) == "/api/v1/docs/SPEC%20A?limit=1"


async def test_time_window_bounds(
    client: AsyncClient, database: Database, key_material: dict[str, Path]
) -> None:
    """**S3**：偏移 ∈ [−30s, +300s]。

    边界余量刻意留大（±60s 级）：服务端判据用的是**它自己取到的时间**，与客户端生成戳之间
    至少差一个 RTT，机器满载时可达秒级。原先用「恰好超界 1s」（+31/−301/−299）会让断言落在
    RTT 抖动带内 → 偶发 200/401 反转（M11 全量第 2 轮实测命中）。语义不变：
    「超出未来容忍应拒」用 +60s 同样成立，且不依赖 RTT 大小。
    """
    await _make_user(database, "alice", "editor", key_material["editor_ed25519"])
    key = signing.load_private_key(key_material["editor_ed25519"])
    now = datetime.now(timezone.utc)

    def stamp(offset_seconds: int) -> str:
        return signing.timestamp_now(now + timedelta(seconds=offset_seconds))

    stale = signing.sign_request_headers(key, "GET", "/api/v1/docs", timestamp=stamp(-400))
    response = await client.get("/api/v1/docs", headers=stale)
    assert response.status_code == 401
    assert response.json()["detail"]["reason"] == "timestamp_expired"

    future = signing.sign_request_headers(key, "GET", "/api/v1/docs", timestamp=stamp(60))
    response = await client.get("/api/v1/docs", headers=future)
    assert response.status_code == 401
    assert response.json()["detail"]["reason"] == "timestamp_future"

    # 窗口**内**（距两侧边界各留 ≥30s：−60s vs 下限 −30s、且远离 +300s 上限）
    inside = signing.sign_request_headers(key, "GET", "/api/v1/docs", timestamp=stamp(-60))
    assert (await client.get("/api/v1/docs", headers=inside)).status_code == 200

    malformed = dict(inside)
    malformed["X-Timestamp"] = "not-a-timestamp"
    response = await client.get("/api/v1/docs", headers=malformed)
    assert response.status_code == 401
    assert response.json()["detail"]["reason"] == "bad_timestamp"


async def test_nonce_replay_is_rejected(
    client: AsyncClient, database: Database, key_material: dict[str, Path]
) -> None:
    await _make_user(database, "alice", "editor", key_material["editor_ed25519"])
    key = signing.load_private_key(key_material["editor_ed25519"])
    headers = signing.sign_request_headers(key, "GET", "/api/v1/docs")

    assert (await client.get("/api/v1/docs", headers=headers)).status_code == 200
    replay = await client.get("/api/v1/docs", headers=headers)
    assert replay.status_code == 401
    assert replay.json()["detail"]["reason"] == "nonce_replay"


async def test_failed_verification_writes_no_nonce(
    client: AsyncClient, database: Database, key_material: dict[str, Path]
) -> None:
    """**S7**：验签未通过 → ``nonces`` 表零写入（未认证请求不写库）。"""
    await _make_user(database, "alice", "editor", key_material["editor_ed25519"])
    key = signing.load_private_key(key_material["editor_ed25519"])
    headers = signing.sign_request_headers(key, "GET", "/api/v1/docs")
    headers["X-SSH-Signature"] = base64.b64encode(b"\x00" * 64).decode()

    before = await _scalar(database, "SELECT count(*) FROM nonces")
    response = await client.get("/api/v1/docs", headers=headers)
    assert response.status_code == 401
    after = await _scalar(database, "SELECT count(*) FROM nonces")
    assert before == after == 0
    assert (
        await _scalar(database, "SELECT count(*) FROM nonces WHERE nonce = :n", n=headers["X-Nonce"])
        == 0
    )


async def test_unregistered_key_is_forbidden_and_audited(
    client: AsyncClient, database: Database, key_material: dict[str, Path]
) -> None:
    """未注册公钥 → 403；审计事件记 ``claimed_key_id`` 且不写身份列（S10）。"""
    await _make_user(database, "alice", "editor", key_material["editor_ed25519"])
    outsider = signing.load_private_key(key_material["outsider_ed25519"])
    headers = signing.sign_request_headers(outsider, "GET", "/api/v1/docs")

    response = await client.get("/api/v1/docs", headers=headers)
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "DTO_AUTH_REJECTED"

    events = await _rows(
        database,
        "SELECT actor, payload FROM events WHERE entity = 'auth' AND op = 'fail' "
        "ORDER BY ts DESC LIMIT 1",
    )
    actor, payload = events[0]
    assert actor == "anonymous"
    assert payload["claimed_key_id"] == headers["X-SSH-Key-Id"]
    assert "user_id" not in payload and "key_fingerprint" not in payload


async def test_role_insufficient_is_403(
    client: AsyncClient, database: Database, key_material: dict[str, Path]
) -> None:
    """签名有效但角色不足 → 403（REQ-M10-F01f）；审计可确定性归因（AUD-4）。"""
    user, _ = await _make_user(database, "bob", "reader", key_material["outsider_ed25519"])
    key = signing.load_private_key(key_material["outsider_ed25519"])
    headers = signing.sign_request_headers(key, "POST", "/api/v1/docs", b"{}")
    response = await client.post("/api/v1/docs", content=b"{}", headers=headers)
    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "forbidden"

    # 授权拒绝发生在**身份已验证之后**：actor 仍为 anonymous（S10 字面），
    # 但 payload 带确定性归因 verified_user_id（与 claimed_* 自述值区分）
    events = await _rows(
        database,
        "SELECT actor, payload FROM events WHERE entity = 'auth' AND op = 'fail' "
        "AND payload->>'reason' = 'forbidden' ORDER BY ts DESC LIMIT 1",
    )
    actor, payload = events[0]
    assert actor == "anonymous"
    assert payload["verified_user_id"] == str(user.user_id)
    assert "claimed_user_id" not in payload


async def test_missing_credentials_is_401_and_exemptions_work(
    client: AsyncClient, database: Database, key_material: dict[str, Path]
) -> None:
    """**S4**：豁免清单外无凭据必 401；清单内端点无需凭据。"""
    await _make_user(database, "alice", "editor", key_material["editor_ed25519"])

    missing = await client.get("/api/v1/docs")
    assert missing.status_code == 401
    assert missing.json()["detail"]["reason"] == "missing_credentials"
    assert missing.headers["WWW-Authenticate"].startswith("SSHSIG")

    assert (await client.get("/healthz")).status_code == 200
    assert (await client.get("/")).status_code == 200
    assert (await client.post("/api/v1/auth/challenge")).status_code == 200

    assert middleware.is_exempt("/healthz") is True
    assert middleware.is_exempt("/api/v1/auth/login") is True
    assert middleware.is_exempt("/assets/login-app.js") is True
    assert middleware.is_exempt("/api/v1/docs") is False
    assert middleware.is_exempt("/docs") is False
    assert middleware.is_exempt("/openapi.json") is False
    assert middleware.is_exempt("/", "POST") is False


@needs_ssh_keygen
async def test_end_to_end_with_real_ssh_keygen_signature(
    client: AsyncClient, database: Database, tmp_path: Path
) -> None:
    """**S11 端到端互操作**：用真实 ``ssh-keygen -Y sign`` 签 HTTP 载荷 → 200。

    模拟 M11 CLI：从私钥生成签名头（签名由 openssh 产出，服务端验签器接受）。
    """
    private = tmp_path / "cli_ed25519"
    subprocess.run(
        [SSH_KEYGEN, "-q", "-N", "", "-t", "ed25519", "-f", str(private)],
        check=True,
        capture_output=True,
    )
    await _make_user(database, "cli", "editor", private)

    timestamp = signing.timestamp_now()
    nonce = signing.new_nonce()
    path = "/api/v1/docs?limit=1"
    payload = signing.request_payload("GET", path, None, timestamp, nonce)
    (tmp_path / "payload").write_bytes(payload)
    subprocess.run(
        [
            SSH_KEYGEN, "-Y", "sign", "-n", sshsig.NAMESPACE,
            "-f", str(private), str(tmp_path / "payload"),
        ],
        check=True,
        capture_output=True,
    )
    signature = Path(f"{tmp_path / 'payload'}.sig").read_text()
    headers = {
        "X-SSH-Key-Id": signing.fingerprint(private.with_suffix(".pub").read_text()),
        "X-SSH-Signature": signature,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
    }
    response = await client.get(path, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["source"] == "agent"


# ------------------------------------------------------ 会话登录路径（F02）


async def _login_with_ssh_key(
    client: AsyncClient, database: Database, key_path: Path
) -> tuple[dict, str]:
    """挑战-响应登录（客户端用私钥签 nonce）→ ``(响应体, token)``。"""
    challenge = (await client.post("/api/v1/auth/challenge")).json()
    key = signing.load_private_key(key_path)
    signature = signing.sign_message(key, signing.login_payload(challenge["nonce"]))
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "keyFingerprint": signing.fingerprint(key_path.with_suffix(".pub").read_text()),
            "nonce": challenge["nonce"],
            "signature": signature,
        },
    )
    assert response.status_code == 200, response.text
    token = response.cookies.get(sessions.SESSION_COOKIE_NAME)
    assert token is not None
    return response.json(), token


async def test_challenge_login_session_and_token_hashing(
    client: AsyncClient, database: Database, key_material: dict[str, Path]
) -> None:
    """REQ-M10-F02 a/e/f + **S13**：token 只存 SHA256、熵 32 字节、Cookie 标志正确。"""
    user, _ = await _make_user(database, "alice", "editor", key_material["editor_ed25519"])
    body, token = await _login_with_ssh_key(client, database, key_material["editor_ed25519"])

    assert body["userId"] == str(user.user_id)
    assert body["username"] == "alice" and body["role"] == "editor"
    assert len(token) >= 43  # token_urlsafe(32) ≈ 43 字符
    rows = await _rows(database, "SELECT token_hash FROM sessions")
    assert rows == [(hashlib.sha256(token.encode()).hexdigest(),)]
    assert await _scalar(database, "SELECT count(*) FROM sessions WHERE token_hash = :t", t=token) == 0

    # 再登录一次，专门检查 Set-Cookie 标志（S6）
    challenge = (await client.post("/api/v1/auth/challenge")).json()
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "keyFingerprint": signing.fingerprint(
                key_material["editor_ed25519"].with_suffix(".pub").read_text()
            ),
            "nonce": challenge["nonce"],
            "signature": signing.sign_message(
                signing.load_private_key(key_material["editor_ed25519"]),
                signing.login_payload(challenge["nonce"]),
            ),
        },
    )
    set_cookie = response.headers["set-cookie"]
    assert "httponly" in set_cookie.lower() and "samesite=lax" in set_cookie.lower()

    client.cookies.set(sessions.SESSION_COOKIE_NAME, token)
    me = await client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["userId"] == str(user.user_id)
    assert me.json()["permissions"] == []


async def test_login_nonce_replay_and_expiry(
    client: AsyncClient, database: Database, key_material: dict[str, Path]
) -> None:
    await _make_user(database, "alice", "editor", key_material["editor_ed25519"])
    challenge = (await client.post("/api/v1/auth/challenge")).json()
    key = signing.load_private_key(key_material["editor_ed25519"])
    payload = {
        "keyFingerprint": signing.fingerprint(
            key_material["editor_ed25519"].with_suffix(".pub").read_text()
        ),
        "nonce": challenge["nonce"],
        "signature": signing.sign_message(key, signing.login_payload(challenge["nonce"])),
    }
    assert (await client.post("/api/v1/auth/login", json=payload)).status_code == 200

    replay = await client.post("/api/v1/auth/login", json=payload)
    assert replay.status_code == 401
    assert replay.json()["detail"]["reason"] == "unknown_challenge"

    expired = (await client.post("/api/v1/auth/challenge")).json()
    async with database.transaction() as session:
        await session.execute(
            text("UPDATE nonces SET seen_at = :ts WHERE nonce = :n"),
            {"ts": datetime.now(timezone.utc) - timedelta(seconds=CHALLENGE_TTL_SECONDS + 1), "n": expired["nonce"]},
        )
    stale = await client.post(
        "/api/v1/auth/login",
        json={
            **payload,
            "nonce": expired["nonce"],
            "signature": signing.sign_message(key, signing.login_payload(expired["nonce"])),
        },
    )
    assert stale.status_code == 401
    assert stale.json()["detail"]["reason"] == "challenge_expired"

    # 坏签名：401 且不消费挑战（S7：验签失败不写库）
    pending = (await client.post("/api/v1/auth/challenge")).json()
    before = await _scalar(database, "SELECT count(*) FROM nonces")
    bad = await client.post(
        "/api/v1/auth/login",
        json={**payload, "nonce": pending["nonce"], "signature": "AAAA"},
    )
    assert bad.status_code == 401
    assert await _scalar(database, "SELECT count(*) FROM nonces") == before
    assert (
        await _scalar(database, "SELECT count(*) FROM nonces WHERE nonce = :n", n=pending["nonce"])
        == 1
    )


async def test_logout_invalidates_cookie(
    client: AsyncClient, database: Database, key_material: dict[str, Path]
) -> None:
    await _make_user(database, "alice", "editor", key_material["editor_ed25519"])
    _, token = await _login_with_ssh_key(client, database, key_material["editor_ed25519"])
    client.cookies.set(sessions.SESSION_COOKIE_NAME, token)

    assert (await client.get("/api/v1/auth/me")).status_code == 200
    logged_out = await client.post("/api/v1/auth/logout")
    assert logged_out.status_code == 204
    assert (await client.get("/api/v1/auth/me")).status_code == 401
    assert await _scalar(database, "SELECT count(*) FROM sessions") == 0

    # 无凭据的 logout 也在豁免清单外 → 401（S4）
    assert (await client.post("/api/v1/auth/logout")).status_code == 401


async def test_disabling_user_kills_keys_and_live_sessions(
    client: AsyncClient, database: Database, key_material: dict[str, Path]
) -> None:
    user, _ = await _make_user(database, "alice", "editor", key_material["editor_ed25519"])
    _, token = await _login_with_ssh_key(client, database, key_material["editor_ed25519"])
    cookies = {sessions.SESSION_COOKIE_NAME: token}
    key = signing.load_private_key(key_material["editor_ed25519"])
    # Cookie 优先于签名头（浏览器路径）；清空 cookie jar 以专测 **agent 签名路径**
    client.cookies.clear()
    assert (
        await client.get(
            "/api/v1/docs", headers=signing.sign_request_headers(key, "GET", "/api/v1/docs")
        )
    ).status_code == 200

    # 由另一 admin 禁用（S9：不能禁用最后一个 active admin，故先建第二个 admin）
    other_admin = await auth_users.create_user("root2", "admin", actor=SYSTEM_ACTOR, db=database)
    await auth_users.update_user(
        user.user_id,
        status="disabled",
        actor=str(other_admin.user_id),
        actor_id=other_admin.user_id,
        db=database,
    )
    assert await auth_users.find_active_key(
        signing.fingerprint(key_material["editor_ed25519"].with_suffix(".pub").read_text()),
        db=database,
    ) is None
    # 签名路径：密钥随属主禁用立即失效 → 403
    signed = await client.get(
        "/api/v1/docs", headers=signing.sign_request_headers(key, "GET", "/api/v1/docs")
    )
    assert signed.status_code == 403
    # 会话路径：既有 Cookie 立即 401（S8）
    client.cookies.set(sessions.SESSION_COOKIE_NAME, token)
    assert (await client.get("/api/v1/auth/me")).status_code == 401
    # 该用户的会话被立即清除（S8 + S15 清理口径）
    assert await _scalar(database, "SELECT count(*) FROM sessions WHERE user_id = :u", u=user.user_id) == 0


async def test_rate_limit_on_challenge(
    client: AsyncClient, monkeypatch, database: Database, key_material: dict[str, Path]
) -> None:
    """**S7**：``/auth/challenge`` 按 IP 限流（``AUTH_RATE_LIMIT_PER_MIN``）。"""
    await _make_user(database, "alice", "editor", key_material["editor_ed25519"])
    monkeypatch.setenv("AUTH_RATE_LIMIT_PER_MIN", "2")
    sessions.reset_rate_limits()

    assert (await client.post("/api/v1/auth/challenge")).status_code == 200
    assert (await client.post("/api/v1/auth/challenge")).status_code == 200
    limited = await client.post("/api/v1/auth/challenge")
    assert limited.status_code == 429
    assert limited.json()["detail"]["reason"] == "rate_limited"


async def test_purge_expired_removes_sessions_and_nonces(
    client: AsyncClient, database: Database, key_material: dict[str, Path]
) -> None:
    """**S15**：过期会话与非ce 同一任务清理（清理后该会话立即 401）。"""
    await _make_user(database, "alice", "editor", key_material["editor_ed25519"])
    _, token = await _login_with_ssh_key(client, database, key_material["editor_ed25519"])
    stale_seconds = sessions.nonce_ttl_seconds() + 5
    async with database.transaction() as session:
        await session.execute(
            text("UPDATE sessions SET expires_at = :ts"),
            {"ts": datetime.now(timezone.utc) - timedelta(seconds=1)},
        )
        await session.execute(
            text("INSERT INTO nonces (nonce, user_id, seen_at) VALUES ('stale-nonce', NULL, :ts)"),
            {"ts": datetime.now(timezone.utc) - timedelta(seconds=stale_seconds)},
        )

    report = await sessions.purge_expired(db=database)
    assert report.sessions == 1 and report.nonces >= 1
    assert await _scalar(database, "SELECT count(*) FROM sessions") == 0
    assert await _scalar(database, "SELECT count(*) FROM nonces WHERE nonce = 'stale-nonce'") == 0
    client.cookies.set(sessions.SESSION_COOKIE_NAME, token)
    assert (await client.get("/api/v1/auth/me")).status_code == 401


def test_cookie_secure_follows_deployment(monkeypatch) -> None:
    """**S6**：非 loopback 部署（TLS 代理终止）→ Cookie 带 ``Secure``。"""
    monkeypatch.delenv("AUTH_COOKIE_SECURE", raising=False)
    monkeypatch.setenv("API_HOST", "127.0.0.1")
    assert middleware.cookie_secure() is False
    assert middleware.session_cookie_kwargs()["secure"] is False

    monkeypatch.setenv("API_HOST", "0.0.0.0")
    assert middleware.cookie_secure() is True
    assert middleware.session_cookie_kwargs()["httponly"] is True
    assert middleware.session_cookie_kwargs()["samesite"] == "lax"

    monkeypatch.setenv("AUTH_COOKIE_SECURE", "0")
    assert middleware.cookie_secure() is False
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "1")
    monkeypatch.setenv("API_HOST", "127.0.0.1")
    assert middleware.cookie_secure() is True


def _request_with(forwarded: str | None, peer: str = "10.0.0.9") -> Request:
    """构造 Starlette ``Request``（仅测 ``client_ip``，无网络）。"""
    headers = [] if forwarded is None else [(b"x-forwarded-for", forwarded.encode())]
    return Request({"type": "http", "method": "GET", "path": "/api/v1/auth/challenge",
                    "headers": headers, "client": (peer, 1234)})


def test_client_ip_uses_last_hop_not_forged_prefix(monkeypatch) -> None:
    """**AUD-1 回归**：信任代理时取**由可信代理追加的**那一段，伪造首段无效。"""
    monkeypatch.setenv("AUTH_TRUSTED_PROXY", "1")
    monkeypatch.delenv("AUTH_PROXY_COUNT", raising=False)
    # 客户端自述 198.51.100.9，反代追加真实对端 203.0.113.7 → 取右起第 1 段
    assert middleware.client_ip(_request_with("198.51.100.9, 203.0.113.7")) == "203.0.113.7"
    assert middleware.client_ip(_request_with("198.51.100.10, 203.0.113.7")) == "203.0.113.7"
    # 双反代：AUTH_PROXY_COUNT=2 → 右起第 2 段
    monkeypatch.setenv("AUTH_PROXY_COUNT", "2")
    assert middleware.client_ip(_request_with("203.0.113.7, 10.0.0.1")) == "203.0.113.7"
    # 链长不足配置层数 → 视为头不可信，回落直连对端（收紧而非放松）
    assert middleware.client_ip(_request_with("198.51.100.9")) == "10.0.0.9"
    assert middleware.client_ip(_request_with(None)) == "10.0.0.9"

    # 未开启信任时完全忽略 XFF
    monkeypatch.delenv("AUTH_TRUSTED_PROXY", raising=False)
    assert middleware.client_ip(_request_with("198.51.100.9, 203.0.113.7")) == "10.0.0.9"


async def test_forged_xff_cannot_bypass_rate_limit(
    client: AsyncClient, monkeypatch, database: Database, key_material: dict[str, Path]
) -> None:
    """**AUD-1 端到端回归**：逐次更换伪造首段，限流仍按可信段生效（429）。"""
    await _make_user(database, "alice", "editor", key_material["editor_ed25519"])
    monkeypatch.setenv("AUTH_TRUSTED_PROXY", "1")
    monkeypatch.setenv("AUTH_RATE_LIMIT_PER_MIN", "2")
    sessions.reset_rate_limits()

    statuses = []
    for octet in range(1, 5):
        # 每次换一个伪造首段，可信反代追加的真段固定为 203.0.113.7
        response = await client.post(
            "/api/v1/auth/challenge",
            headers={"X-Forwarded-For": f"198.51.100.{octet}, 203.0.113.7"},
        )
        statuses.append(response.status_code)
    assert statuses == [200, 200, 429, 429]


def test_auth_coverage_guard_flags_unguarded_routes(app: FastAPI) -> None:
    """**AUD-6**：``is_exempt`` 是可执行断言——漏挂依赖的非豁免路由被查出，合规应用通过。"""
    # 测试用 app 的全部非豁免路由都挂了 require_auth/require_permission
    assert middleware.find_unguarded_routes(app) == []
    middleware.assert_auth_coverage(app)

    unguarded = FastAPI()

    @unguarded.get("/api/v1/secret")
    async def secret() -> dict[str, bool]:  # 漏挂鉴权（模拟未来新增路由）
        return {"ok": True}

    assert middleware.find_unguarded_routes(unguarded) == ["GET /api/v1/secret"]
    with pytest.raises(RuntimeError) as excinfo:
        middleware.assert_auth_coverage(unguarded)
    assert "/api/v1/secret" in str(excinfo.value)

    # 豁免端点不算漏洞路由；FastAPI 自带文档路由默认忽略
    exempt_only = FastAPI()

    @exempt_only.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    assert middleware.find_unguarded_routes(exempt_only) == []


# ------------------------------------------------- 用户 / 密钥 / 授权（F03/F04）


async def test_username_unique_conflict(database: Database) -> None:
    await auth_users.create_user("dup", "editor", actor=SYSTEM_ACTOR, db=database)
    with pytest.raises(ConflictError) as excinfo:
        await auth_users.create_user("dup", "reader", actor=SYSTEM_ACTOR, db=database)
    assert excinfo.value.status_code == 409
    with pytest.raises(ValidationError):
        await auth_users.create_user("bad", "root", actor=SYSTEM_ACTOR, db=database)


async def test_key_registration_rules(
    database: Database, key_material: dict[str, Path]
) -> None:
    alice = await auth_users.create_user("alice", "editor", actor=SYSTEM_ACTOR, db=database)
    bob = await auth_users.create_user("bob", "editor", actor=SYSTEM_ACTOR, db=database)
    admin_line = key_material["admin_ed25519"].with_suffix(".pub").read_text()
    rsa_line = key_material["rsa_3072"].with_suffix(".pub").read_text()

    first = await auth_users.add_ssh_key(alice.user_id, admin_line, actor=SYSTEM_ACTOR, db=database)
    second = await auth_users.add_ssh_key(alice.user_id, rsa_line, actor=SYSTEM_ACTOR, db=database)
    assert {first.key_type, second.key_type} == {"ssh-ed25519", "rsa-sha2-512"}

    with pytest.raises(ConflictError):  # 同一用户重复登记
        await auth_users.add_ssh_key(alice.user_id, admin_line, actor=SYSTEM_ACTOR, db=database)
    with pytest.raises(ConflictError):  # 同一公钥属于他人（身份归属唯一）
        await auth_users.add_ssh_key(bob.user_id, admin_line, actor=SYSTEM_ACTOR, db=database)
    with pytest.raises(ValidationError):  # 公钥不合规 → 422
        await auth_users.add_ssh_key(bob.user_id, "ssh-ed25519 not-base64!!", actor=SYSTEM_ACTOR, db=database)
    with pytest.raises(NotFoundError):
        await auth_users.add_ssh_key(new_uuid7(), admin_line, actor=SYSTEM_ACTOR, db=database)

    # 吊销单个密钥不影响同用户其他密钥（F03c）
    await auth_users.revoke_ssh_key(alice.user_id, first.key_id, actor=SYSTEM_ACTOR, db=database)
    active = await auth_users.list_ssh_keys(alice.user_id, db=database)
    assert [key.key_id for key in active] == [second.key_id]
    revoked = await auth_users.list_ssh_keys(alice.user_id, include_revoked=True, db=database)
    assert len(revoked) == 2
    # 吊销后重新登记复用该行
    readded = await auth_users.add_ssh_key(alice.user_id, admin_line, actor=SYSTEM_ACTOR, db=database)
    assert readded.revoked_at is None
    assert len(await auth_users.list_ssh_keys(alice.user_id, db=database)) == 2


async def test_last_admin_and_self_protection(
    database: Database, admin_pub_path: Path
) -> None:
    """**S9**：不可 disable/demote/delete 自身，也不可操作最后一个 active admin（409）。"""
    admin = await bootstrap.bootstrap_admin(db=database)
    with pytest.raises(ConflictError) as excinfo:
        await auth_users.update_user(
            admin.user_id, role="editor", actor=str(admin.user_id), actor_id=admin.user_id, db=database
        )
    assert excinfo.value.status_code == 409
    with pytest.raises(ConflictError):
        await auth_users.update_user(
            admin.user_id,
            status="disabled",
            actor=str(admin.user_id),
            actor_id=admin.user_id,
            db=database,
        )
    with pytest.raises(ConflictError):  # 最后一个 active admin（由他人操作也不行）
        await auth_users.update_user(
            admin.user_id, role="editor", actor=str(new_uuid7()), actor_id=new_uuid7(), db=database
        )
    with pytest.raises(ConflictError):
        await auth_users.delete_user(
            admin.user_id, actor=str(new_uuid7()), actor_id=new_uuid7(), db=database
        )

    second = await auth_users.create_user("root2", "admin", actor=SYSTEM_ACTOR, db=database)
    demoted = await auth_users.update_user(
        admin.user_id,
        role="editor",
        actor=str(second.user_id),
        actor_id=second.user_id,
        db=database,
    )
    assert demoted.role == "editor"  # 有继任者后允许降级
    assert (await auth_users.get_user(admin.user_id, db=database)).role == "editor"
    # 自身删除仍被拒（即使不是最后一个 admin）
    with pytest.raises(ConflictError):
        await auth_users.delete_user(
            second.user_id, actor=str(second.user_id), actor_id=second.user_id, db=database
        )


async def test_grant_denied_at_grant_time_and_decision_time(
    database: Database, key_material: dict[str, Path]
) -> None:
    """**S5 两处均拒**（REQ-M10-F04e）：授予时 422 + 判定时 403。"""
    reader = await auth_users.create_user("reader1", "reader", actor=SYSTEM_ACTOR, db=database)

    with pytest.raises(ValidationError) as excinfo:
        await auth_users.create_grant(
            reader.user_id, "doc", "SPEC-A", "write", actor=SYSTEM_ACTOR, db=database
        )
    assert excinfo.value.status_code == 422
    with pytest.raises(ValidationError):
        await auth_users.create_grant(
            reader.user_id, "repo", "org/x", "read", actor=SYSTEM_ACTOR, db=database
        )
    with pytest.raises(ValidationError):
        await auth_users.create_grant(
            reader.user_id, "doc", "SPEC-A", "admin", actor=SYSTEM_ACTOR, db=database
        )

    # 绕过服务层直接落库（模拟历史脏数据）→ 判定时仍 403
    async with database.transaction() as session:
        await session.execute(
            text(
                "INSERT INTO grants (grant_id, user_id, scope, value, permission, granted_at) "
                "VALUES (:gid, :uid, 'doc', 'SPEC-A', 'write', now())"
            ),
            {"gid": new_uuid7(), "uid": reader.user_id},
        )
    with pytest.raises(ForbiddenError):
        await auth_users.authorize_user(reader, "write", DocTarget(value="SPEC-A"), db=database)
    # 只读仍可用
    await auth_users.authorize_user(reader, "read", DocTarget(value="SPEC-A"), db=database)


async def test_grant_narrowing_and_revocation(
    database: Database, admin_pub_path: Path
) -> None:
    """REQ-M10-F04 d：收窄范围精确；撤销后恢复角色作用域。"""
    await bootstrap.bootstrap_admin(db=database)
    editor = await auth_users.create_user("ed", "editor", actor=SYSTEM_ACTOR, db=database)
    grant = await auth_users.create_grant(
        editor.user_id, "doc_type", "product", "write", actor=SYSTEM_ACTOR, db=database
    )
    assert grant.scope == "doc_type" and grant.permission == "write"

    await auth_users.authorize_user(
        editor, "write", DocTarget(value="SPEC-P"), doc_type="product", db=database
    )
    with pytest.raises(ForbiddenError):
        await auth_users.authorize_user(
            editor, "write", DocTarget(value="SPEC-S"), doc_type="standard", db=database
        )
    with pytest.raises(ForbiddenError):
        await auth_users.authorize_user(editor, "write", DocTypeTarget(value="standard"), db=database)

    # 重复授予 → 409（唯一约束）
    with pytest.raises(ConflictError):
        await auth_users.create_grant(
            editor.user_id, "doc_type", "product", "write", actor=SYSTEM_ACTOR, db=database
        )

    await auth_users.delete_grant(grant.grant_id, actor=SYSTEM_ACTOR, db=database)
    await auth_users.authorize_user(
        editor, "write", DocTarget(value="SPEC-S"), doc_type="standard", db=database
    )
    with pytest.raises(NotFoundError):
        await auth_users.delete_grant(grant.grant_id, actor=SYSTEM_ACTOR, db=database)


async def test_auth_audit_events_cover_all_mutations(
    database: Database, admin_pub_path: Path, key_material: dict[str, Path]
) -> None:
    """**S1**：``entity='auth'`` 事件可写入且覆盖用户/密钥/授权/登录/失败。"""
    admin = await bootstrap.bootstrap_admin(db=database)
    alice = await auth_users.create_user("alice", "editor", actor=str(admin.user_id), db=database)
    line = key_material["editor_ed25519"].with_suffix(".pub").read_text()
    key = await auth_users.add_ssh_key(alice.user_id, line, actor=str(admin.user_id), db=database)
    await auth_users.revoke_ssh_key(alice.user_id, key.key_id, actor=str(admin.user_id), db=database)
    await auth_users.create_grant(
        alice.user_id, "doc", "SPEC-A", "read", actor=str(admin.user_id), db=database
    )
    await auth_users.update_user(
        alice.user_id, role="reviewer", actor=str(admin.user_id), actor_id=admin.user_id, db=database
    )

    events = await _rows(
        database,
        "SELECT op, actor, payload FROM events WHERE entity = 'auth' ORDER BY ts, event_id",
    )
    ops = [op for op, _, _ in events]
    assert "user_change" in ops and "key_change" in ops and "grant_change" in ops
    assert all(actor for _, actor, _ in events)
    actions = {payload["action"] for _, _, payload in events if "action" in payload}
    assert {"bootstrap_create", "create_user", "add_key", "revoke_key", "add_grant", "update_user"} <= actions
    # 折叠接口可重放 auth 审计（§3.5：仅审计，不参与实体折叠）
    replayed = await auth_users.log_auth_event(
        "fail", "anonymous", {"reason": "manual"}, db=database
    )
    assert replayed.entity == "auth" and replayed.op == "fail"


async def test_session_resolution_slides_expiry(
    client: AsyncClient, database: Database, key_material: dict[str, Path]
) -> None:
    """会话 TTL 8h 滑动续期；未知/过期 token → ``None``（并清行）。"""
    user, _ = await _make_user(database, "alice", "editor", key_material["editor_ed25519"])
    _, token = await _login_with_ssh_key(client, database, key_material["editor_ed25519"])
    (initial_expires,) = (
        await _rows(database, "SELECT expires_at FROM sessions WHERE user_id = :u", u=user.user_id)
    )[0]

    resolved = await sessions.resolve_session(token, db=database)
    assert resolved is not None and resolved.user_id == user.user_id
    (slid_expires,) = (
        await _rows(database, "SELECT expires_at FROM sessions WHERE user_id = :u", u=user.user_id)
    )[0]
    assert slid_expires >= initial_expires  # 每次解析都把 expires_at 前移一个 TTL
    # 滑动幅度 = 两次取时间之间的真实间隔（含 IO），满载时会变大：留 30s 余量而非 5s，
    # 断言语义仍是「滑动是 TTL 量级的有界推进，不是绝对上限/无界累积」
    assert slid_expires - initial_expires < timedelta(seconds=30)

    assert await sessions.resolve_session("bogus-token", db=database) is None
    async with database.transaction() as db_session:
        await db_session.execute(
            text("UPDATE sessions SET expires_at = :ts"),
            {"ts": datetime.now(timezone.utc) - timedelta(seconds=1)},
        )

    assert await sessions.resolve_session(token, db=database) is None
    assert await _scalar(database, "SELECT count(*) FROM sessions") == 0


async def test_delete_user_that_granted_others_is_allowed(
    database: Database, admin_pub_path: Path, key_material: dict[str, Path]
) -> None:
    """回归：``grants.granted_by`` 无级联动作——删曾授出授权的 admin 不得 500。

    ``delete_user`` 先把其授出记录的 ``granted_by`` 置空（**授权本身保留**：被授权人
    不受影响），审计事件记 ``nulled_granted_by`` 计数（S1）。
    """
    # 复现前提（可独立核对）：`grants.granted_by` 的外键是 NO ACTION（`a`），
    # 而 `grants.user_id` 是 CASCADE —— 故直接 DELETE users 必触发 FK 违规（500）
    constraint = await _rows(
        database,
        "SELECT confdeltype FROM pg_constraint "
        "WHERE conname = 'grants_granted_by_fkey'",
    )
    assert constraint[0][0] == b"a"  # confdeltype 为 "char"，asyncpg 返回 bytes

    grantor = await bootstrap.bootstrap_admin(db=database)
    successor = await auth_users.create_user("root2", "admin", actor=SYSTEM_ACTOR, db=database)
    reader = await auth_users.create_user("reader1", "reader", actor=SYSTEM_ACTOR, db=database)
    grant = await auth_users.create_grant(
        reader.user_id, "doc", "SPEC-A", "read", actor=str(grantor.user_id), db=database
    )
    assert grant.granted_by == grantor.user_id

    await auth_users.delete_user(
        grantor.user_id,
        actor=str(successor.user_id),
        actor_id=successor.user_id,
        db=database,
    )
    assert await auth_users.list_users(db=database) != []
    kept = (await auth_users.list_grants(user_id=reader.user_id, db=database))[0]
    assert kept.grant_id == grant.grant_id and kept.granted_by is None
    # 被授权人权限不受影响
    await auth_users.authorize_user(reader, "read", DocTarget(value="SPEC-A"), db=database)
    events = await _rows(
        database,
        "SELECT payload FROM events WHERE entity = 'auth' AND payload->>'action' = 'delete_user'",
    )
    assert events and events[-1][0]["nulled_granted_by"] == 1



async def test_authenticate_rejects_bad_nonce_header(
    client: AsyncClient, database: Database, key_material: dict[str, Path]
) -> None:
    """``X-Nonce`` 熵不足 / 非法字符 → 401（§3 M06：≥128 位随机）。"""
    await _make_user(database, "alice", "editor", key_material["editor_ed25519"])
    key = signing.load_private_key(key_material["editor_ed25519"])
    good = signing.sign_request_headers(key, "GET", "/api/v1/docs")
    for bad_nonce in ("short", "!" * 40):  # 熵不足（<22 字符）/ 非法字符
        headers = {**good, "X-Nonce": bad_nonce}
        response = await client.get("/api/v1/docs", headers=headers)
        assert response.status_code == 401, bad_nonce
        assert response.json()["detail"]["reason"] == "bad_nonce"


async def test_write_context_uses_verified_identity(
    client: AsyncClient, database: Database, key_material: dict[str, Path]
) -> None:
    """S14：身份取自验签结果；``source`` 由凭据类型判定（签名 → ``agent``，Cookie → ``webui``）。"""
    user, _ = await _make_user(database, "alice", "editor", key_material["editor_ed25519"])
    key = signing.load_private_key(key_material["editor_ed25519"])
    headers = signing.sign_request_headers(key, "GET", "/api/v1/docs")
    # 客户端自述头不再存在：X-Actor 被忽略（S14）
    headers["X-Actor"] = "someone-else"
    response = await client.get("/api/v1/docs", headers=headers)
    assert response.status_code == 200
    assert response.json()["actor"] == str(user.user_id)

    ctx = middleware.AuthContext(user=user, source="webui", session_hash="h")
    assert middleware.write_context(ctx) == WriteContext(actor=str(user.user_id), source="webui")

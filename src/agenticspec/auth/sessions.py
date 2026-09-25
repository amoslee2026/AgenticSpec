"""M10 挑战-响应登录、会话与非重放 nonce（REQ-M10-F01/F02；S3/S7/S8/S13/S15）。

**三条短生命周期状态**（全部落库，进程重启不丢）：

============  =================================  ==========================================
表            语义                                 TTL
============  =================================  ==========================================
``nonces``    ① 请求签名 nonce（重放防护）         ``max(2×SIGNATURE_MAX_SKEW_SECONDS, 600s)``（S3）
              ② 登录挑战 nonce（``user_id``         ``120s``（一次性；验签通过后 DELETE）
                 IS NULL`` 标记）
``sessions``  WebUI 会话（库内只存 SHA256）         ``SESSION_TTL_HOURS``（默认 8h，滑动续期）
============  =================================  ==========================================

**为什么挑战 nonce 也落 ``nonces`` 表**：它必须服务端留存才可能「一次性 + TTL」，而 DDL 只有
这五张鉴权表（无 ``challenges`` 表）。挑战签发是**豁免端点唯一的预认证写库动作**，受
``AUTH_RATE_LIMIT_PER_MIN`` 限流；**验签失败不产生任何 nonce 行**（S7 判据）。

**token 熵（S13）**：``secrets.token_urlsafe(32)``（256 位 CSPRNG），库内只存 ``SHA256(token)``，
明文仅出现在 Cookie 与本次响应体。

**会话失效（S8）**：:func:`resolve_session` **JOIN ``users`` 且 ``status='active'``**；未命中
一律删除该 token 对应行 → 禁用用户 / 吊销密钥 / 过期会话的既有请求立即 401。

**清理任务（S15）**：:func:`purge_expired` 在**同一个任务**里清会话与 nonce
（``DELETE WHERE expires_at < now()`` / ``seen_at < now() - nonce_ttl``），并顺带落失败审计的
汇总事件（S7 聚合）；定时触发由 M06/M07 的启动任务调用。
"""

from __future__ import annotations

import hashlib
import os
import secrets
import threading
import time
from collections import deque
from datetime import datetime, timedelta
from typing import Any, Final

from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import IntegrityError

from agenticspec.model import Model, Session, User, new_uuid7
from agenticspec.observability import get_logger
from agenticspec.store import (
    Database,
    ForbiddenError,
    append_event,
    build_model,
    get_database,
    now,
)
from agenticspec.store.rows import row_to_dict
from agenticspec.store.schema import nonces, sessions, users

from .errors import AuthError, AuthenticationError, RateLimitError, SignatureFormatError
from .signing import login_payload, normalize_key_id
from .sshsig import parse_sshsig, verify_sshsig
from .users import fetch_active_key, fetch_user, flush_auth_failure_aggregates, user_from_row


def _bad_signature_error(key_id: str, signature: str) -> AuthenticationError:
    """验签失败的**可操作诊断**：从 SSHSIG 帧内提取签名实际所用公钥指纹，
    区分「用错私钥」与「载荷 nonce 与挑战不一致」两类根因（S11 同验签器复用）。
    """
    try:
        signer = parse_sshsig(signature).fingerprint
    except SignatureFormatError as exc:
        return AuthenticationError(
            f"签名解析失败（{exc.reason}）：请粘贴完整 \"-----BEGIN SSH SIGNATURE-----…-----\" 块",
            reason="bad_signature",
        )
    if signer != key_id:
        return AuthenticationError(
            f"验签失败：该签名由公钥 {signer} 生成，与你填写的指纹 {key_id} 不一致——"
            "请确认签名命令中的私钥路径（-f）就是已注册/你填写的公钥对应私钥",
            reason="bad_signature",
        )
    return AuthenticationError(
        "验签失败：签名确由该公钥生成，但载荷 nonce 不匹配——挑战已过期或已更换，"
        "请回到页面重新获取挑战后在 600s 内签名并提交",
        reason="bad_signature",
    )

__all__ = [
    "CHALLENGE_TTL_SECONDS",
    "SESSION_COOKIE_NAME",
    "Challenge",
    "LoginResult",
    "PurgeReport",
    "challenge_ttl_seconds",
    "check_rate_limit",
    "consume_nonce",
    "create_challenge",
    "future_skew_seconds",
    "login",
    "logout",
    "nonce_ttl_seconds",
    "purge_expired",
    "rate_limit_per_min",
    "reset_rate_limits",
    "resolve_session",
    "session_token_hash",
    "session_ttl_seconds",
    "signature_max_skew_seconds",
]

log = get_logger("m10.sessions")

SESSION_COOKIE_NAME: Final = "agenticspec_session"
"""会话 Cookie 名（httpOnly/SameSite=Lax；Secure 见 :mod:`agenticspec.auth.middleware`）。"""

CHALLENGE_TTL_SECONDS: Final = 600
"""登录挑战 nonce TTL（REQ-M10-F02；600s 给跨机器签名/粘贴留足操作时间）。"""

FUTURE_SKEW_SECONDS: Final = 30
"""未来时间戳容忍（S3：``偏移 ∈ [−30s, +SIGNATURE_MAX_SKEW_SECONDS]``）。"""

_RATE_WINDOW_SECONDS: Final = 60


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def session_ttl_seconds() -> int:
    """会话 TTL（``SESSION_TTL_HOURS``，默认 8h）。"""
    return max(1, _env_int("SESSION_TTL_HOURS", 8)) * 3600


def signature_max_skew_seconds() -> int:
    """过去时间戳容忍（``SIGNATURE_MAX_SKEW_SECONDS``，默认 300s）。"""
    return max(1, _env_int("SIGNATURE_MAX_SKEW_SECONDS", 300))


def future_skew_seconds() -> int:
    """未来时间戳容忍（S3：固定 30s，不可经环境放宽）。"""
    return FUTURE_SKEW_SECONDS


def nonce_ttl_seconds() -> int:
    """nonce 保留期 = ``max(2×时间窗, 600s)``——必须 ≥ 时间窗宽度，否则存在重放窗口（S3）。"""
    return max(2 * signature_max_skew_seconds(), 600)


def rate_limit_per_min() -> int:
    """``/auth/challenge``、``/auth/login`` 的每 IP 每分钟上限（``AUTH_RATE_LIMIT_PER_MIN``）。"""
    return _env_int("AUTH_RATE_LIMIT_PER_MIN", 10)


def challenge_ttl_seconds() -> int:
    """登录挑战 TTL（:data:`CHALLENGE_TTL_SECONDS`，600s）。"""
    return CHALLENGE_TTL_SECONDS


def _db(db: Database | None) -> Database:
    return db if db is not None else get_database()


# ------------------------------------------------------------------- 限流（S7）


_rate_hits: dict[str, deque[float]] = {}
_rate_lock = threading.Lock()
"""**进程内**滑动窗口（与 ``users._failure_buckets`` 同理）。

部署约束（SecAudit AUD-5）：本项目 §5 形态是**单进程** uvicorn（``--workers 1``，systemd
每实例一进程）。多 worker/多实例时各进程独立计数，限流上限会被放大 N 倍、失败聚合也会
重复落事件；届时须把计数外置（PG 的 ``INSERT ... ON CONFLICT`` 或 Redis），本模块接口不变。
"""


def check_rate_limit(ip: str | None, *, limit: int | None = None) -> None:
    """滑动窗口限流（**进程内**；``limit<=0`` 关闭）。超限 → :class:`RateLimitError`（429）。"""
    maximum = rate_limit_per_min() if limit is None else limit
    if maximum <= 0:
        return
    key = ip or "unknown"
    cutoff = time.monotonic() - _RATE_WINDOW_SECONDS
    with _rate_lock:
        hits = _rate_hits.setdefault(key, deque())
        while hits and hits[0] < cutoff:
            hits.popleft()
        if len(hits) >= maximum:
            raise RateLimitError(
                f"too many auth attempts from {key}（>{maximum}/min，S7）", reason="rate_limited"
            )
        hits.append(time.monotonic())


def reset_rate_limits() -> None:
    """清空限流窗口（测试/进程重启用）。"""
    with _rate_lock:
        _rate_hits.clear()


# ------------------------------------------------------------------------ 类型


class Challenge(Model):
    """一次性登录挑战（``POST /auth/challenge`` 响应；TTL 120s）。"""

    nonce: str
    expires_at: datetime


class LoginResult(Model):
    """登录成功结果（``token`` 明文只在此处出现一次，库内仅存 SHA256）。"""

    user: User
    session: Session
    token: str


class PurgeReport(Model):
    """清理任务产出（S15：会话与非ce 同一任务）。"""

    sessions: int
    nonces: int
    failure_aggregates: int


# -------------------------------------------------------------------- 挑战签发


async def create_challenge(ip: str | None = None, *, db: Database | None = None) -> Challenge:
    """签发一次性 nonce（TTL 120s；**按 IP 限流**，S7）。"""
    check_rate_limit(ip)
    nonce = secrets.token_urlsafe(32)
    issued = now()
    expires = issued + timedelta(seconds=CHALLENGE_TTL_SECONDS)
    async with _db(db).transaction() as session:
        await session.execute(insert(nonces).values(nonce=nonce, user_id=None, seen_at=issued))
    log.info("challenge issued", op="create_challenge", expires_at=expires.isoformat())
    return Challenge(nonce=nonce, expires_at=expires)


async def login(
    key_fingerprint: str,
    nonce: str,
    signature: str,
    *,
    db: Database | None = None,
    ip: str | None = None,
) -> LoginResult:
    """挑战-响应登录（REQ-M10-F02）：验签通过后签发会话（S13 token）。

    失败映射：挑战未知/过期/重放 → 401；公钥未注册或其属主被禁用 → 403；验签失败 → 401。
    **验签失败不写任何 nonce 行**（S7），也不消费挑战（整事务回滚）。
    """
    check_rate_limit(ip)
    database = _db(db)
    key_id = normalize_key_id(key_fingerprint)
    stamp = now()
    async with database.transaction() as session:
        row = (
            await session.execute(
                select(nonces.c.seen_at).where(
                    nonces.c.nonce == nonce, nonces.c.user_id.is_(None)
                )
            )
        ).first()
        if row is None:
            raise AuthenticationError(
                "challenge nonce 未知或已被消费（一次性，S7）", reason="unknown_challenge"
            )
        if stamp - row[0] > timedelta(seconds=CHALLENGE_TTL_SECONDS):
            await session.execute(delete(nonces).where(nonces.c.nonce == nonce))
            raise AuthenticationError(
                f"challenge 已过期（TTL {CHALLENGE_TTL_SECONDS}s）", reason="challenge_expired"
            )
        key = await fetch_active_key(session, key_id)
        if key is None:
            raise ForbiddenError(
                f"公钥 {key_id} 未注册或其属主已禁用（S8）", entity="auth", entity_id=key_id
            )
        try:
            verify_sshsig(key["public_key"], signature, login_payload(nonce))
        except AuthError as exc:
            log.warn("login signature rejected", op="login", key_id=key_id, reason=exc.reason)
            raise
        consumed = await session.execute(
            delete(nonces).where(nonces.c.nonce == nonce, nonces.c.user_id.is_(None))
        )
        if consumed.rowcount != 1:
            raise AuthenticationError(
                "challenge 已被消费（并发重放）", reason="challenge_replayed"
            )
        user_row = await fetch_user(session, key["user_id"])
        if user_row is None or user_row["status"] != "active":
            raise ForbiddenError(
                f"用户 {key['user_id']} 不存在或已禁用（S8）",
                entity="auth",
                entity_id=str(key["user_id"]),
            )
        token = secrets.token_urlsafe(32)
        record = {
            "session_id": new_uuid7(),
            "user_id": user_row["user_id"],
            "token_hash": session_token_hash(token),
            "created_at": stamp,
            "expires_at": stamp + timedelta(seconds=session_ttl_seconds()),
            "last_seen_at": stamp,
        }
        await session.execute(insert(sessions).values(**record))
        await append_event(
            session,
            entity="auth",
            entity_id=str(user_row["user_id"]),
            op="login",
            payload={"user_id": str(user_row["user_id"]), "key_fingerprint": key_id, "ip": ip},
            actor=str(user_row["user_id"]),
            ts=stamp,
        )
    log.info("session created", op="login", user_id=str(record["user_id"]), key_id=key_id)
    return LoginResult(
        user=user_from_row(user_row), session=build_model(Session, record), token=token
    )


def session_token_hash(token: str) -> str:
    """``SHA256(token)`` 十六进制（S13：库内只存哈希，明文只存 Cookie）。"""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------------ 会话


async def resolve_session(token: str, *, db: Database | None = None) -> User | None:
    """token → :class:`~agenticspec.model.User`（无效/过期/属主禁用 → ``None``）。

    S8：``JOIN users`` 且 ``status='active'``；未命中时删除该 ``token_hash`` 行（再试即 401）；
    命中则**滑动续期**（``last_seen_at``/``expires_at`` 前移一个 TTL）。
    """
    if not token:
        return None
    token_hash = session_token_hash(token)
    stamp = now()
    async with _db(db).transaction() as session:
        statement = (
            select(
                sessions.c.session_id,
                sessions.c.expires_at,
                users.c.user_id.label("u_user_id"),
                users.c.username,
                users.c.role,
                users.c.status,
                users.c.created_at.label("u_created_at"),
                users.c.updated_at,
            )
            .join(users, users.c.user_id == sessions.c.user_id)
            .where(
                sessions.c.token_hash == token_hash,
                sessions.c.expires_at > stamp,
                users.c.status == "active",
            )
        )
        row = (await session.execute(statement)).first()
        if row is None:
            await session.execute(delete(sessions).where(sessions.c.token_hash == token_hash))
            return None
        data = row_to_dict(row)
        await session.execute(
            update(sessions)
            .where(sessions.c.session_id == data["session_id"])
            .values(
                last_seen_at=stamp,
                expires_at=stamp + timedelta(seconds=session_ttl_seconds()),
            )
        )
    user_row = {
        "user_id": data["u_user_id"],
        "username": data["username"],
        "role": data["role"],
        "status": data["status"],
        "created_at": data["u_created_at"],
        "updated_at": data["updated_at"],
    }
    return user_from_row(user_row)


async def logout(
    token: str | None = None, *, session_id: Any = None, db: Database | None = None
) -> bool:
    """销毁会话（``token`` 或 ``session_id`` 二选一）；返回是否确实删除了会话。"""
    if token is None and session_id is None:
        raise ValueError("logout() needs either token or session_id")
    condition = (
        sessions.c.token_hash == session_token_hash(token)
        if token is not None
        else sessions.c.session_id == session_id
    )
    async with _db(db).transaction() as session:
        row = (await session.execute(select(sessions.c.user_id).where(condition))).first()
        if row is None:
            return False
        user_id = row[0]
        await session.execute(delete(sessions).where(condition))
        await append_event(
            session,
            entity="auth",
            entity_id=str(user_id),
            op="logout",
            payload={"user_id": str(user_id)},
            actor=str(user_id),
            ts=now(),
        )
    log.info("session destroyed", op="logout", user_id=str(user_id))
    return True


# -------------------------------------------------------------------- nonce 消费


async def consume_nonce(
    session: Any, nonce: str, user_id: Any, *, seen_at: datetime | None = None
) -> None:
    """把请求 nonce 写入 ``nonces`` 表（**仅在验签通过后调用**，S7）。

    PK 冲突即重放 → :class:`AuthenticationError`（401）。调用方须处于「写完即提交」的事务中。
    """
    try:
        await session.execute(
            insert(nonces).values(nonce=nonce, user_id=user_id, seen_at=seen_at or now())
        )
    except IntegrityError as exc:
        raise AuthenticationError(
            "nonce 已被使用（重放请求，S3）", reason="nonce_replay"
        ) from exc


# ------------------------------------------------------------------------ 清理


async def purge_expired(
    *, db: Database | None = None, moment: datetime | None = None
) -> PurgeReport:
    """过期清理（S15：会话与非ce 同一任务）+ 失败审计汇总（S7 聚合）。"""
    stamp = moment or now()
    database = _db(db)
    aggregates = await flush_auth_failure_aggregates(db=database)
    async with database.transaction() as session:
        expired_sessions = await session.execute(
            delete(sessions).where(sessions.c.expires_at < stamp)
        )
        stale_nonces = await session.execute(
            delete(nonces).where(nonces.c.seen_at < stamp - timedelta(seconds=nonce_ttl_seconds()))
        )
    report = PurgeReport(
        sessions=expired_sessions.rowcount or 0,
        nonces=stale_nonces.rowcount or 0,
        failure_aggregates=aggregates,
    )
    if report.sessions or report.nonces:
        log.info(
            "expired auth state purged",
            op="purge_expired",
            sessions=report.sessions,
            nonces=report.nonces,
        )
    return report

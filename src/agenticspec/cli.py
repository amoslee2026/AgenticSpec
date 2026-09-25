"""M11 CLI 工具族（架构规范 §3 M11 / §9.2；REQ-M11-F01..F04）——统一入口 ``agenticspec``。

**分两条路径，口径与 WebUI 一致（P5）**：

* **用户级操作**（``doc``/``node``/``comment``/``user``/``grant``/``render``/``stats --health``）
  一律经 **M06/M07 HTTP 端点**（:class:`SigningClient`），由 M10 在服务端做同一套
  鉴权/授权/RBAC 判定——CLI 侧只做「提前给出可操作指引」，不代替服务端裁决。
* **批量数据导入**（``import parse|review|commit``）走 **in-process M03 服务**
  （:func:`agenticspec.importer.run_commit`，``WriteContext(source="importer")``）：
  导入涉及上千节点的单事务写入，逐节点走 HTTP 在 10k 文档规模下不可行；调用前先经
  ``GET /api/v1/auth/me`` 做 editor 角色检查。``auth bootstrap``（建立鉴权本身）与
  ``quality-gate``（M09B 质量门，只读巡检）同属本地库操作，后者的角色门槛由 CLI 按
  detector 判定：数据一致性巡检需 reader，``perf_health``（DB 内部指标）需 admin。

**签名（REQ-M11-F04）**：私钥查找顺序 ``AGENTICSPEC_SSH_KEY`` → ``~/.ssh/id_ed25519``
→ ``~/.ssh/id_rsa``；载荷与验签方共用 :mod:`agenticspec.auth.signing` 的唯一定义点
（``METHOD\\nRAW_PATH(含 query 原样字节)\\nSHA256(body)\\nTIMESTAMP\\nNONCE``）。私钥缺失时
给出**明确错误 + 获取指引**（不抛堆栈）。

**输出**：人可读表格（默认）／``--json`` 结构化（camelCase，与 M06/M07 DTO 同形，
便于 agent 直接消费——skill 的判据之一）。**失败**：非零退出码 + 可操作补救指引
（含所需角色名与授权命令原文，V17c）。

用法::

    uv run agenticspec --help
    uv run agenticspec auth whoami
    uv run agenticspec quality-gate --json
    uv run agenticspec doc list --json
    uv run agenticspec logs stats --group-by error_code
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Final
from urllib.parse import quote, urlencode

import httpx
import typer

from agenticspec.auth import (
    GRANT_PERMISSIONS,
    MANAGE_USERS,
    ROLE_PERMISSIONS,
    SigningError,
    default_key_path,
    fingerprint,
    load_private_key,
    login_payload,
    public_key_line,
    sign_message,
    sign_request_headers,
    validate_public_key,
)
from agenticspec.importer import (
    BULK_ROWS_PER_TRANSACTION,
    run_commit,
    run_parse,
    run_review,
    run_stats,
)
from agenticspec.model import WriteContext
from agenticspec.observability import DTO_AUTH_REJECTED, get_logger, log_dir

__all__ = [
    "API_URL_ENV",
    "DEFAULT_API_URL_PORT",
    "KEY_ENV",
    "CliContext",
    "CliError",
    "Need",
    "SigningClient",
    "app",
    "encode_target",
    "main",
]

log = get_logger("m11.cli")

API_URL_ENV: Final = "AGENTICSPEC_API_URL"
"""API 基址覆盖（缺省 ``http://$API_HOST:$API_PORT``）。"""

KEY_ENV: Final = "AGENTICSPEC_SSH_KEY"
"""私钥路径覆盖（缺省按 :func:`agenticspec.auth.signing.default_key_path` 顺序查找）。"""

PASSPHRASE_ENV: Final = "AGENTICSPEC_SSH_KEY_PASSPHRASE"
"""加密私钥口令（**只经环境变量**，避免出现在 ``ps``/shell 历史里）。"""

USERNAME_ENV: Final = "AGENTICSPEC_USERNAME"
"""本机身份用户名（仅用于把补救指引里的 ``<你的用户名>`` 填实）。"""

LOGGER_BIN: Final = "agentic-logger"
"""M12 日志查询 CLI（ADR-010；``logs`` 子命令是它的薄封装，不重复实现查询）。"""

DEFAULT_API_HOST_PORT: Final = ("127.0.0.1", "8787")
DEFAULT_API_URL_PORT: Final = f"http://{DEFAULT_API_HOST_PORT[0]}:{DEFAULT_API_HOST_PORT[1]}"

DEFAULT_TIMEOUT: Final = 30.0

QUALITY_DEFAULT_DETECTORS: Final = (
    "broken_refs",
    "terms",
    "assets_missing",
    "render_consistency",
    "events_consistency",
    "section_range_consistency",
    "doc_type_schema_conformance",
)
"""``quality-gate`` 缺省跑的 detector：全部**数据一致性**巡检（只读，reader 可跑）。

取值 = ``agenticspec.m09.detector_ids()`` 去掉 :data:`QUALITY_ADMIN_DETECTOR`（声明序前缀，
新增数据 detector 时在此追加即可；`test_quality_gate_default_detectors_exclude_perf_health`
与 e2e 都以本常量为准，不会与 M09 的声明序漂移）。

``perf_health`` 不在缺省内——它读 pg_catalog/连接池等 DB 内部指标，与 ``GET /admin/health``
同级别（admin），故必须显式 ``--detectors perf_health`` 才执行（M10 权限矩阵：manage_users→admin）。
"""

QUALITY_ADMIN_DETECTOR: Final = "perf_health"


BULK_MODES: Final = ("online", "initial_load")
"""``import commit --bulk-mode`` 取值域（M03 批量路径，ADR-009 §3）。"""

_PATH_SAFE: Final = "/-._~!$&'()*+,;=:@"
"""路径中**原样保留**的字符集（其余按 RFC 3986 百分号编码）。

服务端取 ``scope["path"]``（**已解码**）拼签名载荷，故签名用未编码路径、发送用编码路径——
见 :func:`encode_target`。
"""

_ME: Final = "/api/v1/auth/me"

_ROLE_ORDER: Final = ("reader", "reviewer", "editor", "admin")


# ── 错误与权限指引（V17c：权限不足必须给「角色名 + 授权命令原文」）──────────


class CliError(Exception):
    """CLI 面向用户的失败（**不打印堆栈**；消息 + 补救指引 + 退出码）。"""

    def __init__(
        self,
        message: str,
        *,
        hint: Sequence[str] | str | None = None,
        exit_code: int = 1,
        details: Sequence[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.hint = [hint] if isinstance(hint, str) else list(hint or ())
        self.details = list(details or ())
        self.exit_code = exit_code


def _min_role(permission: str) -> str:
    """满足 ``permission`` 的**最低角色**（由 M10 权限矩阵反推，单一事实源）。"""
    if permission == MANAGE_USERS:
        return "admin"
    for role in _ROLE_ORDER:
        if permission in ROLE_PERMISSIONS[role]:
            return role
    raise KeyError(permission)  # pragma: no cover - 取值域由 M10 固定


@dataclass(frozen=True, slots=True)
class Need:
    """一条命令的权限要求（用于预判与 403 补救指引）。"""

    command: str
    permission: str = "read"


def _who() -> str:
    """补救指引中的用户名占位（``AGENTICSPEC_USERNAME`` 或占位符）。"""
    return os.environ.get(USERNAME_ENV) or "<你的用户名>"


def _forbidden_hint(need: Need, *, fingerprint_text: str | None = None) -> list[str]:
    """403 补救指引：包含**所需角色名**与**授权命令原文**（V17c 判据）。"""
    who = _who()
    role = _min_role(need.permission)
    lines = [
        f"权限不足：`{need.command}` 需要 {role} 角色（或等价的文档集级授权）。",
        "由 admin 执行以下命令之一：",
        f"  agenticspec user role --username {who} --role {role}",
    ]
    if need.permission in GRANT_PERMISSIONS:
        lines.append(
            f"  agenticspec grant add --username {who} --scope doc_type "
            f"--value <doc_type|doc_id> --permission {need.permission}"
        )
    else:
        lines.append("（用户管理为 admin 专属，grant 无法提权：只能由现任 admin 授予 admin 角色）")
    if fingerprint_text:
        lines.append(f"你的公钥指纹：{fingerprint_text}（用于核对 users 表登记项）。")
    return lines


def _key_hint(fingerprint_text: str | None = None) -> list[str]:
    """公钥未注册/不可用时的补救指引。"""
    who = _who()
    shown = fingerprint_text or "<你的公钥指纹>"
    return [
        f"你的公钥指纹：{shown}（私钥 → 公钥：ssh-keygen -y -f <私钥>）。",
        "请 admin 登记该公钥：",
        f"  agenticspec user key add --username {who} --key <你的公钥文件，如 ~/.ssh/id_ed25519.pub>",
        "（若用户不存在：先 agenticspec user add --username "
        f"{who} --role editor）",
    ]


def _signing_hint() -> list[str]:
    """私钥缺失/不可读时的获取指引（REQ-M11-F04a）。"""
    return [
        f"私钥查找顺序：${KEY_ENV} → ~/.ssh/id_ed25519 → ~/.ssh/id_rsa。",
        "1) 已有密钥：export "
        f"{KEY_ENV}=~/.ssh/id_ed25519",
        "2) 尚无密钥：ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C agent@$(hostname)",
        f"3) 请 admin 登记公钥：agenticspec user key add --username {_who()} "
        "--key ~/.ssh/id_ed25519.pub",
        f"（加密私钥：export {PASSPHRASE_ENV}=<口令>）",
    ]


def _fail(exc: CliError) -> None:
    """失败输出（stderr）：错误 + 明细 + 补救指引（无堆栈）。"""
    sys.stderr.write(f"错误：{exc.message}\n")
    for line in exc.details:
        sys.stderr.write(f"  {line}\n")
    if exc.hint:
        sys.stderr.write("补救：\n")
        for line in exc.hint:
            sys.stderr.write(f"  · {line}\n" if not line.startswith("  ") else f"{line}\n")
    sys.stderr.flush()


# ── 签名 HTTP 客户端（§3 M11 SigningClient）───────────────────────────────


def api_url() -> str:
    """API 基址（``AGENTICSPEC_API_URL`` → ``http://$API_HOST:$API_PORT``）。"""
    configured = os.environ.get(API_URL_ENV)
    if configured:
        return configured.rstrip("/")
    host = os.environ.get("API_HOST") or DEFAULT_API_HOST_PORT[0]
    port = os.environ.get("API_PORT") or DEFAULT_API_HOST_PORT[1]
    return f"http://{host}:{port}"


def encode_target(path: str, params: Mapping[str, Any] | None = None) -> str:
    """请求行目标：百分号编码的 path + 原样 query（**发送即签名**，S2）。

    服务端取 ASGI ``scope["raw_path"]``（未解码的原样字节，SecAudit AUD-2 后的口径）拼载荷，
    故客户端签的字符串就是**它发出去的这一串**——不再维护「解码形态」这条隐式耦合。
    ``path`` 须给**未编码**形态（如含 ``#``/``·``/非 ASCII 的锚）。
    """
    clean = path if path.startswith("/") else f"/{path}"
    query = urlencode([(key, value) for key, value in (params or {}).items() if value is not None])
    suffix = f"?{query}" if query else ""
    return quote(clean, safe=_PATH_SAFE) + suffix


def _encode_body(body: Any) -> bytes | None:
    """请求体字节（签名对 SHA256(body) 计算，故必须与发送字节逐字节一致）。"""
    if body is None:
        return None
    if isinstance(body, bytes):
        return body
    return json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _dry_response(target: str, method: str, body: bytes | None, key: str | None) -> httpx.Response:
    """``--dry-run`` 的干跑响应（不触网）：把待发请求作为结构化结果返回。"""
    payload = {
        "dryRun": True,
        "method": method.upper(),
        "path": target,
        "body": json.loads(body.decode("utf-8")) if body else None,
        "keyFingerprint": key,
    }
    return httpx.Response(200, json=payload, request=httpx.Request(method.upper(), target))


class SigningClient:
    """自动签名的 M06/M07 HTTP 客户端（§3 M11）。

    ``request()`` 按 §3 M06 载荷规范生成四个签名头；``--dry-run`` 时不触网、不要求私钥，
    只回放「将要发出的请求」（供 skill/agent 干跑与参数自检，V17b）。
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        key_path: str | Path | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        dry_run: bool = False,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = (base_url or api_url()).rstrip("/")
        self.key_path = Path(key_path).expanduser() if key_path else None
        self.timeout = timeout
        self.dry_run = dry_run
        self._transport = transport
        self._key: Any | None = None
        self._client: httpx.Client | None = None

    # -- 私钥 ---------------------------------------------------------------

    @property
    def path(self) -> Path:
        """实际使用的私钥路径（显式 ``--key`` → ``$AGENTICSPEC_SSH_KEY`` → ``~/.ssh/*``）。"""
        return self.key_path or default_key_path()

    def private_key(self) -> Any:
        """加载并缓存私钥（不可用 → :class:`CliError` + 获取指引）。"""
        if self._key is None:
            try:
                self._key = load_private_key(self.path, os.environ.get(PASSPHRASE_ENV))
            except SigningError as exc:
                raise CliError(f"无可用 SSH 私钥：{exc}", hint=_signing_hint()) from exc
        return self._key

    def key_fingerprint(self) -> str:
        """私钥对应公钥指纹（``SHA256:…``）。"""
        return fingerprint(public_key_line(self.private_key()))

    def optional_fingerprint(self) -> str | None:
        """尽力取指纹（干跑/私钥缺失时返回 ``None``，不抛错）。"""
        try:
            return self.key_fingerprint()
        except CliError:
            return None

    # -- 传输 ---------------------------------------------------------------

    def __enter__(self) -> SigningClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.base_url, timeout=self.timeout, transport=self._transport
            )
        return self._client

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        body: Any = None,
        need: Need | None = None,
    ) -> httpx.Response:
        """签名并发送；``>=400`` 转为 :class:`CliError`（含可操作指引）。"""
        raw_body = _encode_body(body)
        target = encode_target(path, params)
        if self.dry_run:
            return _dry_response(target, method, raw_body, self.optional_fingerprint())

        headers = sign_request_headers(self.private_key(), method, target, raw_body)
        if raw_body is not None:
            headers["Content-Type"] = "application/json"
        log.info("cli request", method=method.upper(), path=target, api=self.base_url)
        try:
            response = self._http().request(method.upper(), target, content=raw_body, headers=headers)
        except httpx.HTTPError as exc:
            raise CliError(
                f"无法连接 API（{self.base_url}{target}）：{exc}",
                hint=[
                    "确认服务已启动：uv run agenticspec-api --host 0.0.0.0 --port 8787",
                    f"或指定其它基址：--api-url / ${API_URL_ENV}",
                ],
            ) from exc
        if response.status_code >= 400:
            raise self._http_error(response, target, need)
        return response

    def json(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        body: Any = None,
        need: Need | None = None,
    ) -> Any:
        """请求 + 解析 JSON（``204`` → ``None``）。"""
        response = self.request(method, path, params=params, body=body, need=need)
        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:  # pragma: no cover - 服务端恒返 JSON
            raise CliError(f"响应不是合法 JSON（HTTP {response.status_code}）") from exc

    def _http_error(self, response: httpx.Response, target: str, need: Need | None) -> CliError:
        """HTTP 失败 → :class:`CliError`（§6 错误映射 + 可操作指引）。"""
        status = response.status_code
        detail = _detail(response)
        message = _detail_message(detail) or response.reason_phrase
        code = str(DTO_AUTH_REJECTED) if status in (401, 403) else None
        log.warn(
            "cli request failed",
            method=response.request.method,
            path=target,
            status=status,
            **({"error_code": code} if code else {}),
        )
        shown = self.optional_fingerprint()
        details: list[str] = []
        hints: list[str] = []
        if status == 401:
            hints = [
                "时钟偏移 > SIGNATURE_MAX_SKEW_SECONDS(300s) 或超前 >30s 会被拒：校准 NTP。",
                "nonce 一次性：同一签名不可重放（CLI 每次自动换 nonce）。",
                "库内无 active admin 时系统 fail-closed：先执行 `agenticspec auth bootstrap`。",
            ]
            if shown:
                hints.insert(0, f"当前私钥指纹：{shown}（确认与 users 表中登记的一致）。")
        elif status == 403:
            key_issue = any(word in message for word in ("未注册", "禁用", "revoke", "不可用"))
            if key_issue or shown is None:
                hints = _key_hint(shown)
                if need is not None:
                    hints += _forbidden_hint(need)
            else:
                hints = _forbidden_hint(need, fingerprint_text=shown) if need else _key_hint(shown)
            if shown and not key_issue:
                hints.append(f"当前私钥指纹：{shown}。")
        elif status == 404:
            hints = ["用 `agenticspec doc list` / `agenticspec node get` 确认标识符是否存在。"]
        elif status == 409:
            hints = [
                "乐观锁冲突（版本已变）：重读后重试——agenticspec node get <node_id>",
                "批注/文档状态冲突：先 `agenticspec comment list` 取最新 version。",
            ]
        elif status == 422:
            hints = ["按违规明细修正载荷后重试（字段口径见 `agenticspec node get`）。"]
            details.extend(_violation_lines(detail))
        elif status == 429:
            hints = ["触发限流（AUTH_RATE_LIMIT_PER_MIN）：等待一分钟后重试。"]
        elif status >= 500:
            hints = [
                "服务端内部错误：agenticspec logs query --level ERROR --since 10m --json 看堆栈（含 rid）。",
                "若刚改过代码/依赖，确认服务进程已用新代码重启。",
            ]
        return CliError(
            f"HTTP {status} {message}",
            hint=hints or None,
            details=details or None,
            exit_code=1,
        )


def _detail(response: httpx.Response) -> Any:
    """错误响应负载（优先 ``detail``，M10 为 ``{error, reason, message}``）。"""
    try:
        payload = response.json()
    except ValueError:
        return None
    if isinstance(payload, Mapping) and "detail" in payload:
        return payload["detail"]
    return payload


def _detail_message(detail: Any) -> str | None:
    if isinstance(detail, Mapping):
        for key in ("message", "detail", "error"):
            value = detail.get(key)
            if isinstance(value, str):
                return value
        return json.dumps(detail, ensure_ascii=False)
    if isinstance(detail, list):
        return f"{len(detail)} 项违规"
    if isinstance(detail, str):
        return detail
    return None


def _violation_lines(detail: Any) -> list[str]:
    """422 违规明细（``detail.violations`` 或裸列表）。"""
    items = detail.get("violations") if isinstance(detail, Mapping) else detail
    if not isinstance(items, list):
        return []
    lines: list[str] = []
    for item in items:
        if isinstance(item, Mapping):
            text = item.get("message") or item.get("detail") or json.dumps(item, ensure_ascii=False)
            fix = item.get("fixHint") or item.get("fix_hint")
            lines.append(f"{text}{f'（修正建议：{fix}）' if fix else ''}")
        else:
            lines.append(str(item))
    return lines


# ── 输出（人可读 / --json 结构化）─────────────────────────────────────────


def _emit_json(payload: Any) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n")


def _flat(value: Any) -> str:
    """单元格值 → 单行文本（结构压缩为紧凑 JSON）。"""
    if isinstance(value, (Mapping, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return "" if value is None else str(value)


def _clip(text: str, width: int = 60) -> str:
    return text if len(text) <= width else f"{text[: width - 1]}…"


def _table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    """极简等宽表格（无第三方依赖；列宽自适应）。"""
    cells = [[_clip(_flat(cell)) for cell in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in cells:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip()]
    lines.append("  ".join("-" * widths[i] for i in range(len(headers))))
    lines.extend("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip() for row in cells)
    return "\n".join(lines)


def _kv(payload: Mapping[str, Any]) -> str:
    width = max((len(str(key)) for key in payload), default=0)
    return "\n".join(f"{str(key).ljust(width)}  {_flat(value)}" for key, value in payload.items())


@dataclass
class CliContext:
    """全局选项（``--json`` / ``--dry-run`` / ``--api-url`` / ``--key`` / ``--timeout``）。"""

    json_mode: bool = False
    dry_run: bool = False
    api_url_opt: str | None = None
    key_opt: str | None = None
    timeout: float = DEFAULT_TIMEOUT
    _client: SigningClient | None = field(default=None, repr=False)

    def client(self) -> SigningClient:
        """本命令的签名客户端（复用同一实例，减少连接建立）。"""
        if self._client is None:
            self._client = SigningClient(
                base_url=self.api_url_opt,
                key_path=self.key_opt,
                timeout=self.timeout,
                dry_run=self.dry_run,
            )
        return self._client


def _ctx(context: Any) -> CliContext:
    """取（必要时创建）本进程的 :class:`CliContext`。

    click 传给回调的是它自己的 ``Context``（非 ``typer.Context`` 实例），故按鸭子类型取
    ``obj``；缺失时**回写**到 context 上，保证同一次调用内处处取到同一实例。
    """
    obj = getattr(context, "obj", None)
    if not isinstance(obj, CliContext):
        obj = CliContext()
        if context is not None:
            context.obj = obj
    return obj


def _output(
    context: typer.Context,
    payload: Any,
    *,
    columns: Sequence[tuple[str, str]] | None = None,
    empty: str = "（无结果）",
    human: Callable[[CliContext, Any], None] | None = None,
) -> None:
    """统一输出：``--json``/``--dry-run`` → 结构化；否则表格或键值块。"""
    cli = _ctx(context)
    if cli.json_mode or cli.dry_run:
        _emit_json(payload)
        return
    if human is not None:
        human(cli, payload)
        return
    if payload is None:
        sys.stdout.write("ok\n")
        return
    if isinstance(payload, list):
        if not payload:
            sys.stdout.write(f"{empty}\n")
            return
        keys = [key for key, _ in columns] if columns else list(payload[0])
        headers = [title for _, title in columns] if columns else keys
        rows = [[item.get(key) if isinstance(item, Mapping) else item for key in keys] for item in payload]
        sys.stdout.write(_table(headers, rows) + "\n")
        return
    if isinstance(payload, Mapping):
        sys.stdout.write(_kv(payload) + "\n")
        return
    sys.stdout.write(_flat(payload) + "\n")


def _client_with(context: typer.Context) -> SigningClient:
    """取签名客户端（``need`` 由各命令显式传给 ``json(...)``，用于 403 指引文案）。"""
    return _ctx(context).client()


def _require_identity(client: SigningClient, need: Need) -> Mapping[str, Any]:
    """``GET /auth/me`` + 本地角色预检（import 系命令的 editor 门槛）。"""
    if client.dry_run:
        return {}
    identity = client.json("GET", _ME, need=need)
    if not isinstance(identity, Mapping):  # pragma: no cover - 服务端恒返对象
        raise CliError("身份响应异常（非对象）")
    role = str(identity.get("role") or "")
    if need.permission not in ROLE_PERMISSIONS.get(role, frozenset()):  # type: ignore[arg-type]
        raise CliError(
            f"身份 {identity.get('username')}（{role}）无权执行 `{need.command}`",
            hint=_forbidden_hint(need, fingerprint_text=client.optional_fingerprint()),
        )
    return identity


def _resolve_user_id(client: SigningClient, username: str, need: Need) -> str:
    """用户名 / userId → userId（M07 端点按 ``user_id`` 取资源）。"""
    if _looks_like_uuid(username):
        return username
    users = client.json("GET", "/api/v1/users", params={"status": None}, need=need)
    for user in users if isinstance(users, list) else []:
        if isinstance(user, Mapping) and user.get("username") == username:
            return str(user.get("userId"))
    raise CliError(
        f"用户不存在：{username}",
        hint=[
            f"查看现有用户：agenticspec user list",
            f"新建用户：agenticspec user add --username {username} --role editor",
        ],
    )


def _looks_like_uuid(value: str) -> bool:
    parts = value.split("-")
    return len(parts) == 5 and all(part.isalnum() for part in parts)


def _parse_json_text(text: str, *, source: str) -> Any:
    try:
        return json.loads(text)
    except ValueError as exc:
        raise CliError(f"{source} 不是合法 JSON：{exc}") from exc


def _dry_plan(context: typer.Context, action: str, **arguments: Any) -> bool:
    """in-process 命令的干跑输出（不触库、不触网）；返回是否已处理。"""
    cli = _ctx(context)
    if not cli.dry_run:
        return False
    _emit_json(
        {
            "dryRun": True,
            "action": action,
            "arguments": {
                key: str(value) if isinstance(value, Path) else value for key, value in arguments.items()
            },
            "authCheck": (
                f"GET {_ME}" if action.startswith("import") or action == "quality-gate" else None
            ),
        }
    )
    return True


# ── Typer 装配 ───────────────────────────────────────────────────────────


GLOBAL_FLAGS: Final[tuple[tuple[str, str, str], ...]] = (
    ("json_output", "--json", "结构化输出（camelCase，与 M06/M07 DTO 同形；也可写在子命令之后）"),
    ("dry_run", "--dry-run", "干跑：只回放将要发出的请求，不触网/不写库（也可写在子命令之后）"),
)


def _flag_params() -> tuple[inspect.Parameter, ...]:
    """每条子命令都接受的全局开关（``--json`` / ``--dry-run``）。

    click 的组选项只能写在子命令**之前**；这两个最常用的开关同时注册到每条子命令上
    （值在 :func:`command` 的包装里并入 :class:`CliContext`），于是
    ``agenticspec doc list --json`` 与 ``agenticspec --json doc list`` 等价。
    """
    return tuple(
        inspect.Parameter(
            name,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            default=False,
            annotation=Annotated[bool, typer.Option(flag, help=help_text)],
        )
        for name, flag, help_text in GLOBAL_FLAGS
    )


def command(application: typer.Typer, *args: Any, **kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """注册子命令：统一 (1) 全局开关、(2) :class:`CliError` → 「非零退出 + 可操作指引」。"""

    def decorate(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*fargs: Any, json_output: bool = False, dry_run: bool = False, **fkwargs: Any) -> Any:
            context = fargs[0] if fargs else fkwargs.get("context")
            if context is not None:
                cli = _ctx(context)
                cli.json_mode = cli.json_mode or bool(json_output)
                cli.dry_run = cli.dry_run or bool(dry_run)
            try:
                return func(*fargs, **fkwargs)
            except CliError as exc:
                _fail(exc)
                raise typer.Exit(code=exc.exit_code) from None

        signature = inspect.signature(func, eval_str=True)  # eval_str：注解须为对象，Typer 才能读出 Option 声明
        wrapper.__signature__ = signature.replace(  # type: ignore[attr-defined]
            parameters=[*signature.parameters.values(), *_flag_params()]
        )
        return application.command(*args, **kwargs)(wrapper)

    return decorate


app = typer.Typer(
    name="agenticspec",
    help="AgenticSpec CLI（M11）：结构化文档库的读写/导入/渲染/diff/批注/运维入口。",
    no_args_is_help=True,
    add_completion=False,
)
auth_app = typer.Typer(help="身份：自举 / 自检 / 登录签名（REQ-M11-F04）", no_args_is_help=True)
user_app = typer.Typer(help="用户管理（admin 专属，REQ-M11-F03）", no_args_is_help=True)
key_app = typer.Typer(help="SSH 公钥登记/吊销（admin 专属）", no_args_is_help=True)
grant_app = typer.Typer(help="文档集级授权（admin 专属；角色是硬上限，grant 只收窄）", no_args_is_help=True)
import_app = typer.Typer(help="markdown 导入：解析 → 提议审核 → 事务入库（editor）", no_args_is_help=True)
doc_app = typer.Typer(help="文档读取 / diff / 软删", no_args_is_help=True)
node_app = typer.Typer(help="节点读写（乐观锁）", no_args_is_help=True)
comment_app = typer.Typer(help="批注读写（调取人类标注，B11）", no_args_is_help=True)
logs_app = typer.Typer(help="运行日志查询（薄封装 agentic-logger，ADR-010）", no_args_is_help=True)
mcp_app = typer.Typer(help="MCP server（M13：stdio 标准服务，供 GigaPie/opencode 等 headless agent 挂载）", no_args_is_help=True)

for group, name in (
    (auth_app, "auth"),
    (user_app, "user"),
    (grant_app, "grant"),
    (import_app, "import"),
    (doc_app, "doc"),
    (node_app, "node"),
    (comment_app, "comment"),
    (logs_app, "logs"),
    (mcp_app, "mcp"),
):
    app.add_typer(group, name=name)

user_app.add_typer(key_app, name="key")


@app.callback()
def configure(
    context: typer.Context,
    json_output: Annotated[bool, typer.Option("--json", help="结构化输出（camelCase，与 M06/M07 DTO 同形）")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="干跑：只回放将要发出的请求，不触网/不写库")] = False,
    api_url_opt: Annotated[
        str | None, typer.Option("--api-url", envvar=API_URL_ENV, help=f"API 基址（${API_URL_ENV}）")
    ] = None,
    key_opt: Annotated[
        str | None, typer.Option("--key", envvar=KEY_ENV, help=f"SSH 私钥路径（${KEY_ENV}）")
    ] = None,
    timeout: Annotated[float, typer.Option("--timeout", help="HTTP 超时（秒）")] = DEFAULT_TIMEOUT,
) -> None:
    context.obj = CliContext(
        json_mode=json_output, dry_run=dry_run, api_url_opt=api_url_opt, key_opt=key_opt, timeout=timeout
    )


# ── auth ────────────────────────────────────────────────────────────────


@command(auth_app)
def bootstrap(
    context: typer.Context,
    pubkey: Annotated[
        Path | None,
        typer.Option("--pubkey", envvar="ADMIN_SSH_PUBKEY_FILE", help="admin 公钥文件（默认 $ADMIN_SSH_PUBKEY_FILE）"),
    ] = None,
) -> None:
    """用 ``ADMIN_SSH_PUBKEY_FILE`` 创建首个 admin（幂等；**唯一不签名/不触网的命令**）。"""
    if _dry_plan(context, "auth.bootstrap", pubkey=pubkey or "env:ADMIN_SSH_PUBKEY_FILE"):
        return
    from agenticspec.auth import admin_pubkey_file, bootstrap_admin, has_active_admin, list_ssh_keys
    from agenticspec.store import Database

    target = Path(pubkey).expanduser() if pubkey else admin_pubkey_file()
    if not target.is_file():
        raise CliError(
            f"admin 公钥文件不存在：{target}",
            hint=[
                "把你的公钥放到位：cp ~/.ssh/id_ed25519.pub data/admin_keys/admin.pub",
                "或用 --pubkey / $ADMIN_SSH_PUBKEY_FILE 指定路径。",
            ],
        )

    async def _run() -> tuple[Mapping[str, Any], bool]:
        database = Database()
        try:
            existed = await has_active_admin(db=database)
            user = await bootstrap_admin(target, db=database)
            keys = await list_ssh_keys(user.user_id, db=database)
            payload = {
                "userId": str(user.user_id),
                "username": user.username,
                "role": user.role,
                "status": user.status,
                "created": not existed,
                "keyFile": str(target),
                "keyFingerprints": [key.fingerprint for key in keys],
            }
            return payload, existed
        finally:
            await database.dispose()

    payload, existed = asyncio.run(_run())
    log.info("bootstrap", created=payload["created"], username=payload["username"])
    _output(context, payload)
    if not _ctx(context).json_mode and not _ctx(context).dry_run and existed:
        sys.stdout.write("（已存在 active admin：幂等跳过，以 DB 为准）\n")


@command(auth_app)
def whoami(context: typer.Context) -> None:
    """打印当前身份 / 角色 / 公钥指纹（REQ-M11-F04）。"""
    need = Need(command="auth whoami", permission="read")
    client = _client_with(context)
    identity = client.json("GET", _ME, need=need)
    if not isinstance(identity, Mapping):  # pragma: no cover
        raise CliError("身份响应异常（非对象）")
    payload = {
        **dict(identity),
        "keyFingerprint": client.optional_fingerprint(),
        "apiUrl": client.base_url,
    }
    _output(context, payload)
    if not _ctx(context).json_mode and not _ctx(context).dry_run:
        permissions = payload.get("permissions")
        sys.stdout.write(
            f"（{len(permissions) if isinstance(permissions, list) else 0} 条文档集级授权；"
            "admin 专属操作见 `agenticspec user --help`）\n"
        )


@command(auth_app)
def sign(
    context: typer.Context,
    nonce: Annotated[str | None, typer.Option("--nonce", help="WebUI 登录页显示的一次性 nonce（登录签名）")] = None,
    message: Annotated[str | None, typer.Option("--message", help="对任意文本签名（调试/互操作）")] = None,
    login: Annotated[bool, typer.Option("--login", help="显式声明登录签名（等价于只给 --nonce）")] = False,
) -> None:
    """本地签名：``--login --nonce <n>``（贴回登录页）或 ``--message <文本>``。"""
    if nonce is None and message is None:
        raise CliError(
            "需要 --nonce（登录签名）或 --message（任意文本签名）之一",
            hint=[
                "登录：agenticspec auth sign --login --nonce <登录页显示的 nonce>",
                "调试：agenticspec auth sign --message hello",
            ],
        )
    cli = _ctx(context)
    client = cli.client()
    if login and nonce is None:
        raise CliError("--login 需要同时给 --nonce <登录页显示的 nonce>")
    payload_bytes = login_payload(nonce) if nonce is not None else str(message).encode("utf-8")
    key = client.private_key()
    signature = sign_message(key, payload_bytes)
    payload = {
        "mode": "login" if nonce is not None else "message",
        "keyFingerprint": fingerprint(public_key_line(key)),
        "signature": signature,
    }
    if nonce is not None:
        payload["nonce"] = nonce
    else:
        payload["message"] = message
    if cli.json_mode or cli.dry_run:
        _emit_json(payload)
        return
    sys.stdout.write(f"{signature}\n")


# ── user / key ──────────────────────────────────────────────────────────


def _user_need(command: str) -> Need:
    return Need(command=command, permission=MANAGE_USERS)


@command(user_app, "add")
def add_user(
    context: typer.Context,
    username: Annotated[str, typer.Option("--username", help="用户名（唯一）")],
    role: Annotated[str, typer.Option("--role", help="admin|editor|reviewer|reader")] = "editor",
) -> None:
    """新建用户（admin 专属；落 ``auth`` 审计事件）。"""
    need = _user_need("user add")
    body = {"username": username, "role": role}
    payload = _ctx(context).client().json("POST", "/api/v1/users", body=body, need=need)
    _output(context, payload)


@command(user_app, "list")
def list_user(
    context: typer.Context,
    status: Annotated[str | None, typer.Option("--status", help="active|disabled（缺省全部）")] = None,
) -> None:
    """列出用户。"""
    need = _user_need("user list")
    payload = _ctx(context).client().json(
        "GET", "/api/v1/users", params={"status": status}, need=need
    )
    _output(
        context,
        payload,
        columns=(
            ("userId", "userId"),
            ("username", "username"),
            ("role", "role"),
            ("status", "status"),
            ("createdAt", "createdAt"),
        ),
    )


@command(user_app, "disable")
def disable_user(
    context: typer.Context,
    username: Annotated[str, typer.Option("--username", help="用户名或 userId")],
) -> None:
    """禁用用户（其密钥与会话立即失效，S8；不可禁自身/最后一个 admin）。"""
    need = _user_need("user disable")
    client = _ctx(context).client()
    user_id = _resolve_user_id(client, username, need)
    payload = client.json("PATCH", f"/api/v1/users/{user_id}", body={"status": "disabled"}, need=need)
    _output(context, payload)


@command(user_app, "role")
def set_role(
    context: typer.Context,
    username: Annotated[str, typer.Option("--username", help="用户名或 userId")],
    role: Annotated[str, typer.Option("--role", help="admin|editor|reviewer|reader")],
) -> None:
    """调整用户角色（不可降级自身/最后一个 active admin）。"""
    need = _user_need("user role")
    client = _ctx(context).client()
    user_id = _resolve_user_id(client, username, need)
    payload = client.json("PATCH", f"/api/v1/users/{user_id}", body={"role": role}, need=need)
    _output(context, payload)


@command(key_app, "add")
def add_key(
    context: typer.Context,
    username: Annotated[str, typer.Option("--username", help="用户名或 userId")],
    key: Annotated[Path, typer.Option("--key", help="公钥文件（*.pub）")],
) -> None:
    """登记 SSH 公钥（同一用户可多把；格式/强度不合规本地即拒，422 由服务端兜底）。"""
    need = _user_need("user key add")
    source = Path(key).expanduser()
    if not source.is_file():
        raise CliError(
            f"公钥文件不存在：{source}",
            hint=["导出公钥：ssh-keygen -y -f ~/.ssh/id_ed25519 > ~/.ssh/id_ed25519.pub"],
        )
    line = source.read_text(encoding="utf-8").strip()
    try:
        validate_public_key(line)
    except Exception as exc:  # noqa: BLE001 - auth 抛具体类型不一，统一转 CLI 错误
        raise CliError(f"公钥不合规（{source}）：{exc}", hint=["仅支持 ssh-ed25519 / ssh-rsa（≥2048 位）。"]) from exc
    client = _ctx(context).client()
    user_id = _resolve_user_id(client, username, need)
    payload = client.json("POST", f"/api/v1/users/{user_id}/keys", body={"publicKey": line}, need=need)
    _output(context, payload)


@command(key_app, "revoke")
def revoke_key(
    context: typer.Context,
    username: Annotated[str, typer.Option("--username", help="用户名或 userId")],
    fingerprint_text: Annotated[str, typer.Option("--fingerprint", help="公钥指纹 SHA256:…（= keyId）")],
) -> None:
    """吊销单个公钥（不影响同用户其他密钥）。"""
    need = _user_need("user key revoke")
    client = _ctx(context).client()
    user_id = _resolve_user_id(client, username, need)
    # 指纹走**请求体**（base64 含 `/`、`+`，放路径会被分段/解码吃掉）
    client.json("DELETE", f"/api/v1/users/{user_id}/keys", body={"keyId": fingerprint_text}, need=need)
    _output(context, {"userId": user_id, "keyId": fingerprint_text, "revoked": True})


# ── grant ───────────────────────────────────────────────────────────────


@command(grant_app, "add")
def add_grant(
    context: typer.Context,
    username: Annotated[str, typer.Option("--username", help="用户名或 userId")],
    scope: Annotated[str, typer.Option("--scope", help="doc_type|doc")],
    value: Annotated[str, typer.Option("--value", help="doc_type 值或 doc_id")],
    permission: Annotated[str, typer.Option("--permission", help="read|write|review")],
) -> None:
    """授予文档集级权限（叠加在角色基线之上，**不可超越角色上限**，S5）。"""
    need = _user_need("grant add")
    client = _ctx(context).client()
    user_id = _resolve_user_id(client, username, need)
    body = {"userId": user_id, "scope": scope, "value": value, "permission": permission}
    payload = client.json("POST", "/api/v1/grants", body=body, need=need)
    _output(context, payload)


@command(grant_app, "list")
def list_grant(
    context: typer.Context,
    username: Annotated[str | None, typer.Option("--username", help="只列该用户（缺省全部）")] = None,
) -> None:
    """列出授权。"""
    need = _user_need("grant list")
    client = _ctx(context).client()
    params = {"user_id": _resolve_user_id(client, username, need)} if username else None
    payload = client.json("GET", "/api/v1/grants", params=params, need=need)
    _output(
        context,
        payload,
        columns=(
            ("grantId", "grantId"),
            ("userId", "userId"),
            ("scope", "scope"),
            ("value", "value"),
            ("permission", "permission"),
        ),
    )


@command(grant_app, "rm")
def rm_grant(
    context: typer.Context,
    grant_id: Annotated[str | None, typer.Option("--grant-id", help="授权 ID（直接删）")] = None,
    username: Annotated[str | None, typer.Option("--username", help="或按用户名 + scope/value 定位")] = None,
    scope: Annotated[str | None, typer.Option("--scope", help="doc_type|doc")] = None,
    value: Annotated[str | None, typer.Option("--value", help="doc_type 值或 doc_id")] = None,
    permission: Annotated[str | None, typer.Option("--permission", help="read|write|review（可选，用于消歧）")] = None,
) -> None:
    """撤销授权（``--grant-id`` 或 ``--username --scope --value``）。"""
    need = _user_need("grant rm")
    client = _ctx(context).client()
    target = grant_id
    if target is None:
        if not (username and scope and value):
            raise CliError(
                "需要 --grant-id，或 --username + --scope + --value",
                hint=["先 `agenticspec grant list --username <用户名>` 取 grantId。"],
            )
        user_id = _resolve_user_id(client, username, need)
        grants = client.json("GET", "/api/v1/grants", params={"user_id": user_id}, need=need)
        matched = [
            grant
            for grant in (grants if isinstance(grants, list) else [])
            if isinstance(grant, Mapping)
            and grant.get("scope") == scope
            and grant.get("value") == value
            and (permission is None or grant.get("permission") == permission)
        ]
        if not matched:  # pragma: no cover - 与 list 结果一致的错误路径
            raise CliError(f"未找到匹配授权：{username} {scope}={value}")
        if len(matched) > 1:
            raise CliError(
                f"匹配到 {len(matched)} 条授权，请用 --permission 或 --grant-id 精确指定",
                details=[json.dumps(grant, ensure_ascii=False) for grant in matched],
            )
        target = str(matched[0].get("grantId"))
    client.json("DELETE", f"/api/v1/grants/{target}", need=need)
    _output(context, {"grantId": target, "removed": True})


# ── import（in-process M03；见模块文档字符串的路径说明）───────────────────


@command(import_app, "parse")
def import_parse(
    context: typer.Context,
    src: Annotated[Path, typer.Argument(help="源 markdown（含 frontmatter）")],
    doc_slug: Annotated[str | None, typer.Option("--doc-slug", help="工作区 slug（缺省取文件名）")] = None,
    work_dir: Annotated[Path | None, typer.Option("--work-dir", help="导入工作区根（默认 $IMPORT_WORK_DIR）")] = None,
) -> None:
    """解析 markdown → 原子提议（落 ``proposals.json`` + 初始化 ``review_state.json``）。"""
    if _dry_plan(context, "import.parse", src=src, doc_slug=doc_slug, work_dir=work_dir):
        return
    _require_identity(_client_with(context), Need(command="import parse", permission="write"))
    if not Path(src).is_file():
        raise CliError(f"源文件不存在：{src}", hint=["确认路径，或用绝对路径重试。"])
    result = run_parse(Path(src), doc_slug, work_dir=work_dir)
    payload = result.model_dump(by_alias=True, mode="json")
    _output(context, payload)
    if not _ctx(context).json_mode:
        sys.stdout.write(
            f"（提议 {len(result.proposals)} 条；下一步：agenticspec import review {doc_slug or Path(src).stem}）\n"
        )


@command(import_app, "review")
def import_review(
    context: typer.Context,
    doc_slug: Annotated[str, typer.Argument(help="parse 产出的工作区 slug")],
    work_dir: Annotated[Path | None, typer.Option("--work-dir", help="导入工作区根")] = None,
    actor: Annotated[str | None, typer.Option("--actor", help="审核者（缺省取验签身份 userId）")] = None,
    accept_confident: Annotated[
        bool, typer.Option("--accept-confident", help="先批量通过全部非待确认项（待确认/兜底仍需逐条处置）")
    ] = False,
) -> None:
    """交互式审核提议（逐条 a/r/e/s/u/A/q）→ 更新 ``review_state.json``。"""
    if _dry_plan(context, "import.review", doc_slug=doc_slug, work_dir=work_dir, actor=actor):
        return
    identity = _require_identity(_client_with(context), Need(command="import review", permission="write"))
    who = actor or str(identity.get("username") or "anonymous")
    if _ctx(context).json_mode:
        # `--json` 的输出必须是**纯 JSON**（skill/agent 直接消费）：审核交互从 stdin 取答案，
        # M03 的终端提示音不落 stdout。
        state = run_review(
            doc_slug,
            work_dir=work_dir,
            answers=(line.strip() for line in sys.stdin),
            out=lambda _line: None,
            actor=who,
            accept_confident=accept_confident,
        )
    else:
        state = run_review(
            doc_slug, work_dir=work_dir, actor=who, accept_confident=accept_confident
        )
    payload = state.model_dump(by_alias=True, mode="json")
    _output(context, payload, human=_human_review)


def _human_review(cli: CliContext, payload: Any) -> None:
    items = payload.get("items", {}) if isinstance(payload, Mapping) else {}
    counts: dict[str, int] = {}
    for item in items.values():
        decision = str(item.get("decision"))
        counts[decision] = counts.get(decision, 0) + 1
    sys.stdout.write(_kv({"审核结论": counts, "工作区": payload.get("docSlug")}) + "\n")
    sys.stdout.write(f"（下一步：agenticspec import commit {payload.get('docSlug')}）\n")


@command(import_app, "commit")
def import_commit(
    context: typer.Context,
    doc_slug: Annotated[str, typer.Argument(help="parse/review 产出的工作区 slug")],
    work_dir: Annotated[Path | None, typer.Option("--work-dir", help="导入工作区根")] = None,
    actor: Annotated[str | None, typer.Option("--actor", help="写入者（缺省取验签身份 userId）")] = None,
    source_root: Annotated[Path | None, typer.Option("--source-root", help="资产取件根（默认源 md 所在目录）")] = None,
    no_assets: Annotated[bool, typer.Option("--no-assets", help="跳过图片资产同步")] = False,
    bulk: Annotated[bool, typer.Option("--bulk", help="批量路径（COPY + 每批一事务，ADR-009 §3）")] = False,
    bulk_mode: Annotated[str, typer.Option("--bulk-mode", help="online=在线增量（默认）；initial_load=仅空文档全量装载")] = "online",
    batch_size: Annotated[int, typer.Option("--batch-size", help="每批行数（批量路径）")] = BULK_ROWS_PER_TRANSACTION,
) -> None:
    """校验 + 事务入库（docs/nodes/refs/events）+ 资产同步（``--bulk`` 走批量路径）。"""
    if bulk_mode not in BULK_MODES:
        raise CliError(
            f"未知 --bulk-mode：{bulk_mode}",
            hint=[f"可选：{'、'.join(BULK_MODES)}（online=在线增量；initial_load=仅空文档全量装载）"],
        )
    if _dry_plan(
        context,
        "import.commit",
        doc_slug=doc_slug,
        work_dir=work_dir,
        actor=actor,
        bulk=bulk,
        bulk_mode=bulk_mode,
        batch_size=batch_size,
    ):
        return
    identity = _require_identity(_client_with(context), Need(command="import commit", permission="write"))
    report = asyncio.run(
        run_commit(
            doc_slug,
            work_dir=work_dir,
            ctx=WriteContext(actor=actor or str(identity.get("userId") or "importer"), source="importer"),
            sync_assets_too=not no_assets,
            source_root=source_root,
            bulk=bulk,
            bulk_mode=bulk_mode,  # type: ignore[arg-type]
            batch_size=batch_size,
        )
    )
    payload = report.model_dump(by_alias=True, mode="json")
    _output(context, payload, human=_human_commit)


def _human_commit(cli: CliContext, payload: Any) -> None:
    sys.stdout.write(
        _kv(
            {
                "docId": payload.get("docId"),
                "docType": payload.get("docType"),
                "已入库": payload.get("accepted"),
                "已拒绝": payload.get("rejected"),
                "待确认": payload.get("pending"),
                "工作区": payload.get("workDir"),
            }
        )
        + "\n"
    )
    violations = payload.get("violations") or []
    if violations:
        sys.stdout.write(f"（违规 {len(violations)} 条：{_flat(violations[:3])}）\n")


# ── doc ─────────────────────────────────────────────────────────────────


@command(doc_app, "list")
def doc_list(
    context: typer.Context,
    status: Annotated[str | None, typer.Option("--status", help="draft|reviewed|approved（缺省全部）")] = None,
) -> None:
    """文档清单（含 version/status）。"""
    payload = _ctx(context).client().json(
        "GET", "/api/v1/docs", params={"status": status}, need=Need(command="doc list", permission="read")
    )
    _output(
        context,
        payload,
        columns=(
            ("docId", "docId"),
            ("docType", "docType"),
            ("title", "title"),
            ("status", "status"),
            ("version", "version"),
            ("updatedAt", "updatedAt"),
        ),
    )


@command(doc_app, "get")
def doc_get(context: typer.Context, doc_id: Annotated[str, typer.Argument(help="doc_id（= frontmatter spec_id）")]) -> None:
    """文档详情。"""
    payload = _ctx(context).client().json(
        "GET", f"/api/v1/docs/{doc_id}", need=Need(command="doc get", permission="read")
    )
    _output(context, payload, human=_human_doc)


def _human_doc(cli: CliContext, payload: Any) -> None:
    if not isinstance(payload, Mapping):  # pragma: no cover
        sys.stdout.write(_flat(payload) + "\n")
        return
    meta = payload.get("meta") or {}
    sys.stdout.write(
        _kv(
            {
                "docId": payload.get("docId"),
                "title": payload.get("title"),
                "docType": payload.get("docType"),
                "status": payload.get("status"),
                "version": payload.get("version"),
                "updatedAt": payload.get("updatedAt"),
                "meta": meta,
            }
        )
        + "\n"
    )


@command(doc_app, "diff")
def doc_diff(
    context: typer.Context,
    doc_id: Annotated[str, typer.Argument(help="doc_id")],
    from_: Annotated[str | None, typer.Option("--from", help="起始时间戳或版本（缺省=上一次变更前）")] = None,
    to: Annotated[str | None, typer.Option("--to", help="结束时间戳或版本（缺省=当前）")] = None,
) -> None:
    """文档版本 diff（events 重放，REQ-M11-F02 / REQ-M07-F06）。"""
    payload = _ctx(context).client().json(
        "GET",
        f"/api/v1/docs/{doc_id}/diff",
        params={"from": from_, "to": to},
        need=Need(command="doc diff", permission="read"),
    )
    _output(context, payload, human=_human_diff)


def _human_diff(cli: CliContext, payload: Any) -> None:
    changes = payload.get("changes") if isinstance(payload, Mapping) else None
    summary = payload.get("summary") if isinstance(payload, Mapping) else None
    if not changes:
        sys.stdout.write("（无变更）\n")
    else:
        rows = [
            [
                change.get("nodeId"),
                change.get("anchor"),
                change.get("op"),
                change.get("field"),
                change.get("before"),
                change.get("after"),
            ]
            for change in changes
            if isinstance(change, Mapping)
        ]
        sys.stdout.write(_table(["nodeId", "anchor", "op", "field", "before", "after"], rows) + "\n")
    if summary:
        sys.stdout.write(f"汇总：{_flat(summary)}\n")


@command(doc_app, "delete")
def doc_delete(
    context: typer.Context,
    doc_id: Annotated[str, typer.Argument(help="doc_id")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="跳过确认（非交互环境必需）")] = False,
) -> None:
    """软删文档：**级联软删其全部 active 节点**（逐节点事件 + 服务端 RBAC 裁决）。"""
    cli = _ctx(context)
    need = Need(command="doc delete", permission="write")
    if cli.dry_run:
        _emit_json(
            {
                "dryRun": True,
                "action": "doc.delete",
                "docId": doc_id,
                "plan": [
                    f"GET /api/v1/docs/{doc_id}/nodes",
                    "DELETE /api/v1/nodes/{nodeId}?expected_version={version}（逐个 active 节点）",
                ],
                "atomic": False,
            }
        )
        return
    client = _client_with(context)
    nodes = client.json("GET", f"/api/v1/docs/{doc_id}/nodes", need=need)
    targets = [
        (str(node.get("nodeId")), int(node.get("version") or 1))
        for node in (nodes if isinstance(nodes, list) else [])
        if isinstance(node, Mapping) and node.get("status") != "deleted"
    ]
    if not targets:
        _output(context, {"docId": doc_id, "deleted": [], "notDeleted": [], "atomic": False})
        return
    if not yes and not _confirmed(f"将软删 {doc_id} 的 {len(targets)} 个节点，继续？"):
        raise CliError("已取消（需要 --yes 时表示非交互确认）", exit_code=1)
    deleted: list[str] = []
    failed: Mapping[str, Any] | None = None
    for node_id, version in targets:
        try:
            client.json(
                "DELETE",
                f"/api/v1/nodes/{node_id}",
                params={"expected_version": version},
                need=need,
            )
        except CliError as exc:
            failed = {"nodeId": node_id, "error": exc.message}
            break
        deleted.append(node_id)
    remaining = [node_id for node_id, _ in targets if node_id not in set(deleted)]
    payload = {
        "docId": doc_id,
        "deleted": deleted,
        "notDeleted": remaining,
        "failed": failed,
        "atomic": False,
        "note": "文档软删为逐节点操作（非原子）；如需原子文档级删除请由服务端提供 DELETE /api/v1/docs/{id}",
    }
    _output(context, payload, human=_human_doc_delete)
    if failed is not None:
        raise CliError(
            f"级联软删中断于节点 {failed['nodeId']}：{failed['error']}",
            hint=[
                f"已删 {len(deleted)} 个，未删 {len(remaining)} 个（本命令非原子）。",
                f"排障后重跑即从当前状态继续：agenticspec doc delete {doc_id} --yes",
            ],
            exit_code=1,
        )


def _human_doc_delete(cli: CliContext, payload: Any) -> None:
    sys.stdout.write(
        f"软删 {payload.get('docId')}：已删 {len(payload.get('deleted') or [])} 个节点，"
        f"未删 {len(payload.get('notDeleted') or [])} 个（非原子：逐节点 DELETE）。\n"
    )


def _confirmed(question: str) -> bool:
    """交互确认（非 TTY 视为拒绝，要求显式 ``--yes``）。"""
    if not sys.stdin.isatty():
        return False
    sys.stdout.write(f"{question} [y/N] ")
    sys.stdout.flush()
    return sys.stdin.readline().strip().lower() in ("y", "yes")


# ── node ────────────────────────────────────────────────────────────────


@command(node_app, "get")
def node_get(
    context: typer.Context,
    node_id: Annotated[str, typer.Argument(help="node_id（UUID7）")],
    doc_id: Annotated[str | None, typer.Option("--doc", help="doc_id（传则分区裁剪，V16）")] = None,
) -> None:
    """节点读取（含 ``version``；``--doc`` 传则分区裁剪，缺省全分区扫=降级）。"""
    payload = _ctx(context).client().json(
        "GET",
        f"/api/v1/nodes/{node_id}",
        params={"doc_id": doc_id},
        need=Need(command="node get", permission="read"),
    )
    _output(context, payload)


@command(node_app, "put")
def node_put(
    context: typer.Context,
    file: Annotated[Path | None, typer.Option("--file", help="节点写入 JSON（NodeIn camelCase + expectedVersion）")] = None,
    content: Annotated[str | None, typer.Option("--content", help="内联 content JSON（配合 --doc/--atom-type/--anchor）")] = None,
    doc_id: Annotated[str | None, typer.Option("--doc", help="doc_id")] = None,
    atom_type: Annotated[str | None, typer.Option("--atom-type", help="八类原子之一")] = None,
    anchor: Annotated[str | None, typer.Option("--anchor", help="锚（文档内唯一）")] = None,
    node_id: Annotated[str | None, typer.Option("--node-id", help="更新已有节点时给 node_id")] = None,
    expected_version: Annotated[int | None, typer.Option("--expected-version", help="乐观锁版本（更新必填）")] = None,
    ordinal: Annotated[int | None, typer.Option("--ordinal", help="文档内序号（缺省 0）")] = None,
    level: Annotated[int | None, typer.Option("--level", help="标题层级（可选）")] = None,
    parent: Annotated[str | None, typer.Option("--parent", help="父 node_id（可选）")] = None,
    format_: Annotated[str, typer.Option("--format", help="md|html|text")] = "md",
) -> None:
    """结构化写入/更新（乐观锁：``expectedVersion`` 不匹配 → 409，重读后重试）。"""
    if file is not None:
        source = Path(file).expanduser()
        if not source.is_file():
            raise CliError(f"载荷文件不存在：{source}", hint=["示例见 `agenticspec node get <node_id> --json` 的输出。"])
        body = _parse_json_text(source.read_text(encoding="utf-8"), source=str(source))
        if not isinstance(body, Mapping):
            raise CliError(f"{source} 顶层必须是 JSON 对象（NodeIn + expectedVersion）")
        body = dict(body)
    elif content is not None:
        missing = [
            name for name, value in (("--doc", doc_id), ("--atom-type", atom_type), ("--anchor", anchor)) if not value
        ]
        if missing:
            raise CliError(
                "内联写入需要 " + "、".join(missing),
                hint=[
                    "用法：agenticspec node put --doc <doc_id> --atom-type clause --anchor <锚> "
                    "--content '{\"text\":\"…\"}' [--expected-version N]"
                ],
            )
        # NodeIn 的可选字段（nodeId/parentNodeId/level）**无默认值**（M01 extra=forbid 契约）：
        # 必须显式给 null，否则服务端 422。
        body = {
            "nodeId": node_id,
            "docId": doc_id,
            "atomType": atom_type,
            "format": format_,
            "ordinal": ordinal or 0,
            "parentNodeId": parent,
            "level": level,
            "anchor": anchor,
            "content": _parse_json_text(content, source="--content"),
        }
    else:
        raise CliError(
            "需要 --file 或 --content 之一",
            hint=["推荐：agenticspec node put --file patch.json（NodeIn camelCase + expectedVersion）"],
        )
    if expected_version is not None:
        body["expectedVersion"] = expected_version
    payload = _ctx(context).client().json(
        "POST", "/api/v1/nodes", body=body, need=Need(command="node put", permission="write")
    )
    _output(context, payload)


@command(node_app, "delete")
def node_delete(
    context: typer.Context,
    node_id: Annotated[str, typer.Argument(help="node_id（UUID7）")],
    expected_version: Annotated[int, typer.Option("--expected-version", help="乐观锁版本（必填）")],
    doc_id: Annotated[str | None, typer.Option("--doc", help="doc_id（可选，用于排障提示）")] = None,
) -> None:
    """软删节点（写 delete 事件 + 关联批注置 orphaned）。"""
    payload = _ctx(context).client().json(
        "DELETE",
        f"/api/v1/nodes/{node_id}",
        params={"expected_version": expected_version},
        need=Need(command="node delete", permission="write"),
    )
    _output(context, payload if payload is not None else {"nodeId": node_id, "deleted": True, "docId": doc_id})


# ── comment ─────────────────────────────────────────────────────────────


@command(comment_app, "list")
def comment_list(
    context: typer.Context,
    doc: Annotated[str | None, typer.Option("--doc", help="按文档筛选（与 --node 二选一）")] = None,
    node: Annotated[str | None, typer.Option("--node", help="按节点筛选（与 --doc 二选一）")] = None,
    state: Annotated[str | None, typer.Option("--state", help="open|resolved|orphaned（缺省全部）")] = None,
    with_context: Annotated[
        bool, typer.Option("--with-context", help="附批注锚定版本（targetEventId）处的节点快照")
    ] = False,
) -> None:
    """列出批注（人类标注调取的底层命令，B11/REQ-M11-F06）。"""
    if bool(doc) == bool(node):
        raise CliError(
            "需要 --doc 或 --node 之一（且仅一个）",
            hint=[
                "按文档：agenticspec comment list --doc <doc_id> --state open",
                "按节点：agenticspec comment list --node <node_id>",
            ],
        )
    cli = _ctx(context)
    need = Need(command="comment list", permission="read")
    client = cli.client()
    payload = client.json(
        "GET",
        "/api/v1/comments",
        params={"doc_id": doc, "node_id": node, "state": state},
        need=need,
    )
    comments = payload if isinstance(payload, list) else []
    if with_context and not cli.dry_run:
        for comment in comments:
            if isinstance(comment, Mapping):
                _attach_context(client, comment, need)
    _output(
        context,
        payload,
        columns=(
            ("commentId", "commentId"),
            ("state", "state"),
            ("author", "author"),
            ("nodeId", "nodeId"),
            ("targetEventId", "targetEventId"),
            ("body", "body"),
        ),
    )


def _attach_context(client: SigningClient, comment: Mapping[str, Any], need: Need) -> None:
    """把批注锚定版本处的节点快照挂到批注上（REQ-M11-F06b）。"""
    anchor_event = comment.get("targetEventId")
    if not anchor_event:
        return
    snapshot = client.json(
        "GET",
        "/api/v1/events/replay",
        params={"node_id": comment.get("nodeId"), "upto": anchor_event},
        need=need,
    )
    if isinstance(snapshot, Mapping):
        node = snapshot.get("node")
        comment["context"] = {
            "anchorEventId": anchor_event,
            "historyCount": len(snapshot.get("history") or []),
            "nodeMissing": node is None,
            "node": node,
        }


@command(comment_app, "add")
def comment_add(
    context: typer.Context,
    node: Annotated[str, typer.Option("--node", help="被批注的 node_id")],
    body: Annotated[str | None, typer.Option("--body", help="批注正文")] = None,
    file: Annotated[Path | None, typer.Option("--file", help="从文件读正文（长文本）")] = None,
    expected_version: Annotated[
        int | None, typer.Option("--expected-version", help="被批注节点的版本（可选，乐观锁）")
    ] = None,
) -> None:
    """新建批注（open）。锚点（``targetEventId``）由服务端取该节点最近事件后回填。"""
    if body is None and file is None:
        raise CliError("需要 --body 或 --file 之一", hint=["agenticspec comment add --node <node_id> --body '…'"])
    text = body if body is not None else Path(file).expanduser().read_text(encoding="utf-8")  # type: ignore[union-attr]
    request: dict[str, Any] = {"nodeId": node, "body": text}
    if expected_version is not None:
        request["expectedVersion"] = expected_version
    payload = _ctx(context).client().json(
        "POST",
        "/api/v1/comments",
        body=request,
        need=Need(command="comment add", permission="review"),
    )
    _output(context, payload)


@command(comment_app, "resolve")
def comment_resolve(
    context: typer.Context,
    comment_id: Annotated[str, typer.Argument(help="comment_id（UUID7）")],
    expected_version: Annotated[int, typer.Option("--expected-version", help="乐观锁版本（必填）")],
    state: Annotated[str, typer.Option("--state", help="resolved|open")] = "resolved",
) -> None:
    """批注流转（resolved；``--state open`` 可重新打开）。"""
    payload = _ctx(context).client().json(
        "PATCH",
        f"/api/v1/comments/{comment_id}",
        body={"state": state, "expectedVersion": expected_version},
        need=Need(command="comment resolve", permission="review"),
    )
    _output(context, payload)


# ── render / stats / logs ───────────────────────────────────────────────


@command(app, "render")
def render_doc(
    context: typer.Context,
    doc_id: Annotated[str, typer.Argument(help="doc_id")],
    section: Annotated[str | None, typer.Option("--section", help="只渲染该锚的 level-1/2 章节子树")] = None,
    out: Annotated[Path | None, typer.Option("--out", help="另存 markdown 到本地文件")] = None,
    markdown: Annotated[bool, typer.Option("--markdown", help="把 markdown 打印到 stdout")] = False,
) -> None:
    """渲染整档 / 单章节为 Markdown（HTML 片段零改写直通）。"""
    payload = _ctx(context).client().json(
        "GET",
        f"/api/v1/docs/{doc_id}/render",
        params={"section": section},
        need=Need(command="render", permission="read"),
    )
    cli = _ctx(context)
    if out is not None and isinstance(payload, Mapping):
        target = Path(out).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(payload.get("markdown") or ""), encoding="utf-8")
        if not cli.json_mode:
            sys.stdout.write(f"{target}\n")
            return
        payload = {**payload, "savedTo": str(target)}
    if cli.json_mode or cli.dry_run:
        _emit_json(payload)
        return
    if isinstance(payload, Mapping):
        if markdown:
            sys.stdout.write(str(payload.get("markdown") or ""))
            if not str(payload.get("markdown") or "").endswith("\n"):
                sys.stdout.write("\n")
            return
        sys.stdout.write(
            _kv(
                {
                    "outPath": payload.get("outPath"),
                    "section": payload.get("section"),
                    "assetsExported": payload.get("assetsExported"),
                    "markdownBytes": len(str(payload.get("markdown") or "").encode("utf-8")),
                }
            )
            + "\n"
        )
        return
    _output(context, payload)


@command(app, "stats")
def stats(
    context: typer.Context,
    doc_slug: Annotated[str | None, typer.Argument(help="导入工作区 slug（缺省需 --src）")] = None,
    src: Annotated[Path | None, typer.Option("--src", help="直接对源文件现算覆盖率")] = None,
    work_dir: Annotated[Path | None, typer.Option("--work-dir", help="导入工作区根")] = None,
    health: Annotated[bool, typer.Option("--health", help="容量健康巡检（admin；ADR-010 §3.3）")] = False,
) -> None:
    """导入统计/覆盖率（本地，M03）或容量健康巡检（``--health``，HTTP admin）。"""
    if health:
        payload = _ctx(context).client().json(
            "GET", "/api/v1/admin/health", need=Need(command="stats --health", permission=MANAGE_USERS)
        )
        _output(context, payload, human=_human_health)
        return
    if _dry_plan(context, "stats.import", doc_slug=doc_slug, src=src, work_dir=work_dir):
        return
    if src is None and not doc_slug:
        raise CliError(
            "需要 doc_slug 或 --src 之一（或 --health 走容量巡检）",
            hint=[
                "agenticspec stats <doc_slug>",
                "agenticspec stats --src spec/standards/amba/IHI0024_AMBA_APB_spec.md",
                "agenticspec stats --health",
            ],
        )
    payload = run_stats(src=src, doc_slug=doc_slug, work_dir=work_dir)
    _output(context, payload, human=_human_stats)


def _human_stats(cli: CliContext, payload: Any) -> None:
    if not isinstance(payload, Mapping):  # pragma: no cover
        sys.stdout.write(_flat(payload) + "\n")
        return
    sys.stdout.write(_kv(payload) + "\n")


def _human_health(cli: CliContext, payload: Any) -> None:
    if not isinstance(payload, Mapping):  # pragma: no cover
        sys.stdout.write(_flat(payload) + "\n")
        return
    sys.stdout.write(
        _kv({key: value for key, value in payload.items() if key not in ("tables", "indexes", "partitions", "advice")})
        + "\n"
    )
    advice = payload.get("advice") or []
    if advice:
        sys.stdout.write("建议：\n")
        for line in advice:
            sys.stdout.write(f"  · {line}\n")



@command(app, "quality-gate")
def quality_gate(
    context: typer.Context,
    detectors: Annotated[
        list[str] | None,
        typer.Option(
            "--detectors",
            help="要跑的 detector（可重复或逗号分隔）；缺省=全部数据一致性 detector",
        ),
    ] = None,
    doc_ids: Annotated[
        list[str] | None, typer.Option("--doc-id", help="只巡检这些文档（可重复；缺省全库）")
    ] = None,
) -> None:
    """质量门巡检（M09B 的 detector；只读）——输出按 detector 分组的违规与修复建议。"""
    targets = _resolve_detectors(detectors)
    need = Need(
        command="quality-gate",
        permission=MANAGE_USERS if QUALITY_ADMIN_DETECTOR in targets else "read",
    )
    if _dry_plan(context, "quality-gate", detectors=targets, docIds=doc_ids):
        return
    _require_identity(_client_with(context), need)
    payload = _quality_gate_payload(targets, doc_ids)
    _output(context, payload, human=_human_quality_gate)


def _resolve_detectors(requested: list[str] | None) -> list[str]:
    """``--detectors`` → 归一后的 detector id 序列（未登记即报错，列出可选值）。"""
    from agenticspec.m09 import detector_ids, resolve_detectors
    from agenticspec.store import ValidationError

    wanted = [item.strip() for value in requested or [] for item in value.split(",") if item.strip()]
    try:
        return list(resolve_detectors(wanted or list(QUALITY_DEFAULT_DETECTORS)))
    except (ValidationError, ValueError) as exc:
        raise CliError(
            f"未知 detector：{exc}",
            hint=[
                "可选：" + "、".join(detector_ids()),
                f"缺省（不传 --detectors）：{'、'.join(QUALITY_DEFAULT_DETECTORS)}",
                f"`{QUALITY_ADMIN_DETECTOR}` 巡检 DB 内部指标（pg_catalog/连接池），需 admin 角色。",
            ],
        ) from exc


def _quality_gate_payload(targets: Sequence[str], doc_ids: list[str] | None) -> dict[str, Any]:
    """跑质量门 → 结构化结果（按 detector 分组 + 汇总）。"""
    from agenticspec.m09 import QualityScope, run_quality_gate_sync

    reports = run_quality_gate_sync(
        QualityScope(doc_ids=list(doc_ids) if doc_ids else None, detectors=list(targets))
    )
    rows = [report.model_dump(by_alias=True, mode="json") for report in reports]
    by_detector = {str(row["detectorId"]): len(row["violations"]) for row in rows}
    total = sum(by_detector.values())
    return {
        "detectors": list(targets),
        "docIds": list(doc_ids) if doc_ids else None,
        "reports": rows,
        "summary": {"detectors": len(rows), "violations": total, "byDetector": by_detector},
        "clean": total == 0,
    }


def _human_quality_gate(cli: CliContext, payload: Any) -> None:
    """人可读输出：按 detector 分组；无违规时显式说明（非空输出）。"""
    if not isinstance(payload, Mapping):
        sys.stdout.write(_flat(payload) + "\n")
        return
    reports = payload.get("reports") or []
    for report in reports:
        violations = report.get("violations") or []
        detector_id = report.get("detectorId")
        if not violations:
            sys.stdout.write(f"[{detector_id}] 无违规\n")
            continue
        sys.stdout.write(f"[{detector_id}] 违规 {len(violations)} 条\n")
        rows = [
            [item.get("ruleId"), item.get("path"), item.get("message"), item.get("fixHint")] for item in violations
        ]
        sys.stdout.write(_table(["ruleId", "path", "message", "fixHint"], rows) + "\n")
    summary = payload.get("summary") or {}
    scope = "、".join(payload.get("docIds") or ["全库"])
    sys.stdout.write(
        f"合计：{summary.get('detectors')} 个 detector、{summary.get('violations')} 条违规"
        f"（范围：{scope}）{'；质量门通过（无违规）' if payload.get('clean') else ''}\n"
    )

@command(logs_app, "stats")
def logs_stats(
    context: typer.Context,
    group_by: Annotated[str | None, typer.Option("--group-by", help="level|tool|module|error_code|pid")] = None,
    since: Annotated[str | None, typer.Option("--since", help="起始时间（ISO 8601 或 1h/24h/7d）")] = None,
    until: Annotated[str | None, typer.Option("--until", help="结束时间")] = None,
    rid: Annotated[str | None, typer.Option("--rid", help="按请求 rid 过滤")] = None,
) -> None:
    """日志聚合统计（错误分布 / 模块健康度）。"""
    _run_logger(context, "stats", _opts(group_by=group_by, since=since, until=until, rid=rid))


@command(logs_app, "trace")
def logs_trace(
    context: typer.Context,
    rid: Annotated[str, typer.Option("--rid", help="请求 rid（鉴权→API→存储→渲染）")],
    include_traceback: Annotated[bool, typer.Option("--include-traceback", help="附异常堆栈")] = False,
    module: Annotated[str | None, typer.Option("--module", help="按模块过滤（支持 * 通配）")] = None,
) -> None:
    """单请求全链路追踪。"""
    _run_logger(
        context,
        "trace",
        _opts(
            rid=rid,
            module=module,
            **({"include_traceback": include_traceback} if include_traceback else {}),
        ),
    )


@command(logs_app, "tail")
def logs_tail(
    context: typer.Context,
    follow: Annotated[bool, typer.Option("--follow", "-f", help="持续跟踪新日志")] = False,
    module: Annotated[str | None, typer.Option("--module", help="按模块过滤（如 m02.nodes）")] = None,
    level: Annotated[str | None, typer.Option("--level", help="DEBUG|INFO|WARN|ERROR|…")] = None,
    error_code: Annotated[str | None, typer.Option("--error-code", help="业务错误码（如 DTO_AUTH_REJECTED）")] = None,
) -> None:
    """实时日志（``-f`` 持续跟踪）。"""
    _run_logger(
        context,
        "tail",
        _opts(follow=follow, module=module, level=level, error_code=error_code),
    )


@command(logs_app, "query")
def logs_query(
    context: typer.Context,
    level: Annotated[str | None, typer.Option("--level", help="DEBUG|INFO|WARN|ERROR|TOOL|FILE_OP|…")] = None,
    module: Annotated[str | None, typer.Option("--module", help="按模块过滤（支持 * 通配）")] = None,
    error_code: Annotated[str | None, typer.Option("--error-code", help="业务错误码")] = None,
    rid: Annotated[str | None, typer.Option("--rid", help="按请求 rid 过滤")] = None,
    keyword: Annotated[str | None, typer.Option("--keyword", help="全文关键词")] = None,
    since: Annotated[str | None, typer.Option("--since", help="起始时间（ISO 8601 或 1h/24h/7d）")] = None,
    until: Annotated[str | None, typer.Option("--until", help="结束时间")] = None,
    limit: Annotated[int | None, typer.Option("--limit", help="返回条数上限")] = None,
) -> None:
    """条件查询日志条目。"""
    _run_logger(
        context,
        "query",
        _opts(
            level=level,
            module=module,
            error_code=error_code,
            rid=rid,
            keyword=keyword,
            since=since,
            until=until,
            limit=limit,
        ),
    )


def _opts(**values: Any) -> list[str]:
    """``{name: value}`` → ``["--name", "value"]``（``None``/``False`` 跳过，``True`` 只给开关）。"""
    argv: list[str] = []
    for name, value in values.items():
        if value is None or value is False:
            continue
        flag = f"--{name.replace('_', '-')}"
        if value is True:
            argv.append(flag)
        else:
            argv.extend([flag, str(value)])
    return argv


def _run_logger(context: typer.Context, subcommand: str, options: Sequence[str]) -> None:
    """薄封装 ``agentic-logger``（ADR-010：查询实现不在本仓库重复）。"""
    cli = _ctx(context)
    argv = [LOGGER_BIN, "--log-dir", str(log_dir()), subcommand, *options]
    if cli.json_mode or cli.dry_run:
        argv.extend(["--format", "json"])
    if cli.dry_run:
        _emit_json({"dryRun": True, "action": "logs", "argv": argv})
        return
    binary = shutil.which(LOGGER_BIN)
    if binary is None:
        raise CliError(
            f"未找到 {LOGGER_BIN}（M12 日志查询 CLI）",
            hint=[
                "安装依赖：uv sync（agentic-logger>=0.1.4）",
                f"或直接调用：uv run {LOGGER_BIN} --log-dir {log_dir()} {subcommand} --help",
            ],
        )
    argv[0] = binary
    log.info("delegate to agentic-logger", argv=argv)
    completed = subprocess.run(argv, check=False)  # noqa: S603 - 参数由本模块构造
    if completed.returncode != 0:
        raise CliError(
            f"{LOGGER_BIN} {subcommand} 退出码 {completed.returncode}",
            hint=[f"查看用法：{LOGGER_BIN} {subcommand} --help"],
            exit_code=completed.returncode or 1,
        )


def main(argv: Sequence[str] | None = None) -> None:
    """进程入口（``python -m agenticspec.cli``；console script 直接用 ``app``）。"""
    app(args=list(argv) if argv is not None else None, prog_name="agenticspec")


if __name__ == "__main__":  # pragma: no cover - 进程入口
    main()

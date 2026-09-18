---
title: 用户手册 — 芯片设计知识库系统
type: narrative
purpose: guide
audience: both
direction: output
status: approved
version: "1.4.0"
section_meta: "@meta"
---

# 用户手册

生成：2026-09-16（it.arch Phase 3/4）。**v1.4 更新**（依批注 B1–B11 与用户要求）——新增鉴权、CLI 工具族、监控与性能评估章节。

面向三类使用者：**Agent 操作者**（coding agent / 工程脚本，经 CLI/HTTP）、**人类评审者**（WebUI）、**管理员**（用户与权限管理）。命令行与界面细节在 it.mas/it.tdd 细化；本手册定义使用路径与预期行为。

> **运行期不依赖 LLM（P6）**：本系统运行路径不调用任何 LLM——`coding agent` 只是**外部调用方**（通过 CLI/HTTP 访问），系统在无 LLM 凭据、断网环境下全功能可用。

## 0. 部署与首次启动（管理员）

```bash
# 环境（uv 管理，Python 3.11）
uv sync                                  # 安装依赖（含 agentic-logger）

# 1) 管理员自举（首次必做，否则系统 fail-closed：所有请求 401）
cp ~/.ssh/id_ed25519.pub data/admin_keys/admin.pub   # 你的公钥
uv run alembic upgrade head              # 建库 + 载入 seed（terms）
uv run agenticspec auth bootstrap       # 创建首个 admin（幂等）

# 2) 启动服务
uv run agenticspec-api --host 127.0.0.1 --port 8787 # 开发调试；常驻用 systemd user 单元（scripts/agenticspec-api.service）
```

> **LAN 访问（ADR-007 S6）**：非环回访问不直接 `--host 0.0.0.0`，必须经 TLS 反向代理终止（否则会话 Cookie 可被嗅探）。
> 一键配置：`sudo bash scripts/provision_lan_tls_httpd.sh`（自签证书 + httpd 443 反代 127.0.0.1:8787），然后浏览器访问 `https://<LAN_IP>/`。

**注意**：无 `users` 表记录时系统拒绝所有请求（fail-closed 设计）——这是有意为之，避免「忘记配鉴权即裸奔」。

## 1. 快速开始（Agent 操作者）

**前置**：你的 SSH 公钥已在 `users` 表登记（由 admin 执行 `agenticspec user key add`）。CLI 自动读取 `~/.ssh/` 或 `AGENTICSPEC_SSH_KEY` 私钥签名，无需手工处理鉴权。

```bash
# 身份自检
uv run agenticspec auth whoami          # 显示 user_id / role / 公钥指纹

# 导入一份规范文档（三步骤：解析 → 审核 → 入库）
uv run agenticspec import parse spec/standards/amba/IHI0024_AMBA_APB_spec.md
uv run agenticspec import review IHI0024_AMBA_APB_spec       # 逐条审核
uv run agenticspec import commit IHI0024_AMBA_APB_spec       # 校验+事务入库

# 读写（需 editor 角色）
uv run agenticspec node get SPEC-STD-AMBA-APB#3.2.1
uv run agenticspec node put --file patch.json               # 含 expectedVersion（乐观锁）

# 版本与渲染
uv run agenticspec doc diff SPEC-STD-AMBA-APB --from 2026-09-01
uv run agenticspec render SPEC-STD-AMBA-APB                  # 整档（build/rendered/）
uv run agenticspec render SPEC-STD-AMBA-APB --section 3.2    # 单章节（<1s）

# 调取人类批注（agent 专用 skill 的底层命令）
uv run agenticspec comment list --doc SPEC-STD-AMBA-APB --state open
```

**Skill 用法**（coding agent 侧，`skills/` 目录）：`spec-import` / `spec-read` / `spec-write` / `spec-render` / `spec-diff` / **`spec-annotations`**（调取人类标注）。

## 2. 导入与审核（半自动流程）

1. **parse**：解析器产出原子提议，逐条带 `rule_id` 与「待确认」标志；同时输出未映射块清单。
2. **review**：人工/agent 逐条处置（通过/拒绝/修正）；「待确认」项必须显式确认；未映射块默认兜底（`note`/`code`）保留。
3. **commit**：经 schema 校验后事务入库；失败则报违规明细，修改提议后重试。

**验收口径**：规则覆盖率（携带 `rule_id` 的源块 ÷ 总源块）≥95%；兜底率与待确认条数在审核输出中报告。

**权限**：`import *` 需 editor 角色。

## 3. 结构化读写（M06 API）

- **鉴权**：所有端点（含读）需 SSH 签名。请求头 `X-SSH-Signature`/`X-SSH-Key-Id`/`X-Timestamp`/`X-Nonce`；签名载荷 = `METHOD\nPATH\nSHA256(body)\nTimestamp\nNonce`。CLI 自动完成（§1）；手写脚本可用 `agenticspec auth sign` 辅助。
- 读：按 `node_id` / `doc_id` / `anchor`（如 `SPEC-STD-AMBA-APB#3.2.1·transfer`；重复标题带 `~正文摘要` 后缀）取节点。
- 写：提交 JSON Schema 约束的节点变更 + 当前 `version`（乐观锁）。校验失败 → 违规清单+修复建议；冲突（409）→ 重读后重试。
- 每次成功写入自动：写事件（字段级 diff）→ 更新实体 → 触发该文档重渲染。

## 4. 检索

**本系统只提供确定性读写与文档树浏览**；检索能力归属 LightRAG：

| 需求 | 途径 |
|---|---|
| 按 ID/锚直取节点 | `agenticspec node get`（M06） |
| 浏览文档树/章节树 | `agenticspec doc get`、`GET /docs/{id}/sections` |
| 关键词/语义检索 | **LightRAG**（本系统经 M-LR 提供导出包：渲染文本 + node_id + 增量事件流） |

> **注**：M05 的图遍历与 FTS 为**内部实现**（供 M-LR 导出与质量门），不暴露端点（ADR-008）。

## 2. 导入与审核（半自动流程）

1. **parse**：解析器产出原子提议，逐条带 `rule_id` 与「待确认」标志；同时输出未映射块清单。
2. **review**：人工/agent 逐条处置（通过/拒绝/修正）；「待确认」项必须显式确认；未映射块默认兜底（`note`/`code`）保留。
3. **commit**：经 schema 校验后事务入库；失败则报违规明细，修改提议后重试。

**验收口径**：规则覆盖率（携带 `rule_id` 的源块 ÷ 总源块）≥95%；兜底率与待确认条数在审核输出中报告。

## 5. 评审（人类评审者，WebUI）

### 5.1 登录（SSH 挑战-响应，非密码）

1. 打开 WebUI → 登录页显示一次性 nonce（TTL 120s）。
2. 本地签名：`uv run agenticspec auth sign --login --nonce <nonce>`（读取你的 SSH 私钥），将结果粘回页面。
3. 验签通过 → 签发会话 Cookie（httpOnly，8 小时滑动续期）。

> 浏览器不读取私钥（安全禁区）；登录依赖本地 CLI 辅助签名。

### 5.2 操作

| 操作 | 说明 | 最低角色 |
|---|---|---|
| 浏览 | 按文档/节点树浏览；表单由 schema 自动生成 | reader |
| 分章节加载 | 进入文档先取章节清单，按需拉取渲染结果（单章节 <1s） | reader |
| 结构化 diff | 每次变更按字段级并排展示新旧值（非行级 diff） | reader |
| 批注 | 针对 node_id 留言（open）；解决后置 resolved；节点删除后保留并标 orphaned | reviewer |
| 状态流转 | draft → reviewed → approved（记录到事件日志） | reviewer |
| 版本历史 | 按事件重放查看任意版本；批注显示于其锚定版本旁 | reader |
| 表格编辑 | 仅当文档开启 `editable_tables` 时，表格可编辑并回写 | editor |
| 用户与权限管理 | 增删用户、登记/吊销 SSH 公钥、授予角色与文档集级权限 | **admin** |

## 6. 监控与性能评估（ADR-010）

```bash
# 错误分布 / 模块健康度
uv run agenticspec logs stats --group-by error_code
uv run agenticspec logs stats --group-by module

# 单请求全链路追踪（鉴权→API→存储→渲染）
uv run agenticspec logs trace --rid <rid>

# 实时跟踪 / 条件查询
uv run agenticspec logs tail --module m02.nodes
uv run agenticspec logs query --level ERROR --since 1h

# 容量健康巡检（分区/索引膨胀/连接池/归档逾期）
uv run agenticspec stats --health

# 质量门巡检（M09B 数据一致性 detector；按 detector 分组输出违规 + 修复建议 fixHint）
uv run agenticspec quality-gate --json
uv run agenticspec quality-gate --detectors broken_refs,terms --doc-id SPEC-STD-AMBA-APB
uv run agenticspec quality-gate --detectors perf_health          # 需 admin（DB 内部指标）

# 离线性能基准（验收证据）
uv run pytest tests/perf/ -m perf --benchmark-json=build/perf.json
```

**指标查询（admin）**：`GET /api/v1/admin/metrics?since=&window=`（API 耗时/慢查询/鉴权失败/渲染）、`GET /api/v1/admin/health`。

**日志位置**：`logs/*.jsonl`（AgenticLogger，30 天/500MB 轮转，超出归档 `logs/archive/`）。
**审计**：审计事件在 PG `events` 表（append-only，不可丢弃）——与运行日志分离。

## 7. 常见问题

| 问题 | 处置 |
|---|---|
| 所有请求返回 401 | 系统 fail-closed：未自举或未登记公钥。执行 `agenticspec auth bootstrap` 或请 admin 登记（`user key add`） |
| 403 但密钥有效 | 角色权限不足：请 admin 授予对应角色或文档集级 grant（`grant add`） |
| 签名被拒（401） | 检查时钟偏移（>300s 拒绝）、nonce 是否被复用、请求体是否被中间层改写 |
| WebUI 登录页打不开 | 确认服务已启动且静态资源挂载正常；登录页本身豁免鉴权 |
| 解析出现大量「待确认」 | 正常——按批复核；高频模式可增补解析规则（rule_id 可追溯） |
| 图片渲染缺失 | 查 M09B `assets.missing` 清单；确认 GigaRAG `corpus/02_converted/.../auto/images/` 有实物 |
| 写入返回 409 | 乐观锁冲突：重读节点（含最新 version）后重试 |
| 渲染产物在哪 | `build/rendered/`（可重建，不入库）；`spec/` 内 markdown 是导入快照，勿直接编辑 |
| 为何系统内搜不到 | 检索归 LightRAG（ADR-008）；本系统只提供导出包与按 ID 点查 |
| 为何不能向 lightRAG 导入 | 用户指令暂缓（C7）；系统就绪后按 M-LR 导出包接口联调 |
| 性能不达标 | `agenticspec stats --health` 看巡检建议；`tests/perf/` 复现基准 |

## 8. 用户与权限管理（管理员）

```bash
# 用户
uv run agenticspec user add --username alice --role editor
uv run agenticspec user list
uv run agenticspec user role --username alice --role reviewer
uv run agenticspec user disable --username alice

# SSH 公钥（用户可登记多把，换机无需重建账号）
uv run agenticspec user key add --username alice --key ~/alice.pub
uv run agenticspec user key revoke --username alice --fingerprint SHA256:...

# 文档集级授权（叠加在角色基线之上，不可超越角色上限）
uv run agenticspec grant add --username alice --scope doc_type --value product --permission write
uv run agenticspec grant list --username alice
```

**四角色权限**（详见架构 §3 M10 权限矩阵）：admin（全部 + 用户管理）/ editor（文档 CRUD、批注、表格编辑）/ reviewer（批注、状态审批、只读正文）/ reader（只读）。

## 9. 数据与恢复

- 权威源 = PostgreSQL（database `agenticspec`）；一切变更可凭 `events` 重放。
- 备份：`pg_dump agenticspec`（纳入 sys-backup 惯例）+ git（代码与 spec/ 文档）。
- 迁移：Alembic 管理 DDL 版本（`uv run alembic upgrade head`）。
- **审计不可丢**：`events` 表 append-only；运行日志（`logs/`）可轮转丢弃，二者职责分离。

> [!NOTE]
> **Annotations present.** This file contains reviewer feedback.
> `==highlights==` flag text for discussion. `%%comments%%` are inline notes (hidden in preview, visible in source).
> `~~deletions~~` suggest removal. `> [!EDIT]` blocks are change requests. `> [!TODO]` blocks are instructions to execute.
> These markers are intentional — do not remove or "clean up" without asking the reviewer.

---
title: 架构规范 — 芯片设计知识库系统
type: composite
purpose: architecture
audience: both
direction: input
status: approved
version: "1.4.0"
section_meta: "@meta"
---

# 架构规范

生成：2026-09-16（it.arch Phase 4）。上游：`functional_specification.md`、`../idea/design_doc.md` v1.1.0。

> **v1.2 修订**（A1–A25 闭环）：锚策略（A1）、软删语义（A2）、WriteContext/actor（A3）、comments 乐观锁（A4）、refs 主键（A5）、资产存储与端点（A6）、HTML `<img>` 覆盖（A7）、M08 schema 端点（A8）、渲染签名（A9）、FTS 生成列（A10）、序列化口径（A11）、CLI 统一（A12）、提议持久化（A13）、类型定义补全（A14）、角色/GRANT（A15）、schema/terms 写入路径（A16）、docs 级方法（A17）、事件 fold 规范（A18）、跳数语义（A19）、可测判据（A20，落在 functional_spec）、summary_report（A21）、frontmatter 映射（A22）、悬空引用（A23）、手册路径（A24）、Agent Context/分层/依赖矩阵/非功能（A25）。

> **批注处置（2026-09-16，B1–B11）**：本版依用户批注修订为 v1.3。逐条对应见 §8「批注处置表」；新增模块 M10（鉴权与用户管理）、新增 ADR-007/008、新增 §9 CLI 与 Skill。**批注原文保留在各处原位，不删除**（评审要求）。

> [!TODO] agent写入需要鉴权，通过启动agent的人类用户的ssh公钥进行鉴定身份
>
> **处置（B2/B3）**：已落地，见 §9.1 鉴权模型、ADR-007、§4 鉴权五表（`users`/`ssh_keys`/`grants`/`sessions`/`nonces`）、M10 契约。批注语义扩展为「全体端点（含读）均需鉴权」（用户确认），WebUI 以 SSH 挑战-响应换取会话 Cookie。



## 1. 原则、Agent Context 与依赖规则

> **编号命名空间（V11 修复——阅读本文档前必读）**：本项目存在**三套独立编号**，极易混淆，现明确区分：
> | 前缀 | 含义 | 出处 | 示例 |
> |---|---|---|---|
> | **`P#`** | 架构**原则**不变量（§1.1） | 本文档 | `P6` = 运行期 LLM 无关 |
> | **`A#`** | **it.arch 首轮对抗评审**问题编号（v1.2 时期，A1–A25） | `functional_specification.md` §3、`.review/issues.md` | `A2` = 软删语义 |
> | **`B#`** | **用户批注**编号（2026-09-16，B1–B11） | 本文档 §8「批注处置表」 | `B2` = SSH 鉴权 |
> | **`S#`** | 安全专项评审问题（SecAuthReview，S1–S16） | `functional_specification.md` §安全评审 |
> | **`V#`** | 架构专项评审问题（ArchV13Review，V1–V24） | 同上 |
> | **`REQ-M##-F##`** | 功能需求编号 | `functional_specification.md` | `REQ-M10-F01` |
>
> **注意**：`idea/clarifications.md` 的假设台账使用**自己的** `B1–B16`——与本文档「批注 B#」**撞号但含义不同**。引用 idea 层假设时一律写作 **`idea-B#`**（如 `idea-B6` = 原「单机无鉴权」假设）。

> [!TODO] 应该提供CLI和skill ，供coding agent调用
>
> **处置（B3/B11）**：已落地，见 §9.2 CLI 工具族、§9.3 Skill 清单。


### 1.1 原则（可验证的不变量）

| # | 原则 | 验证方式 |
|---|---|---|
| P1 | 结构化库为唯一权威源；人类可读格式均为渲染产物 | 无代码路径从渲染产物反向写库 |
| P2 | 一切写入 = 事件 + 实体同事务；events 仅追加 | 事务注入测试；角色 REVOKE 审计（§4.1 角色与权限） |
| P3 | 依赖单向：模块仅依赖已交付模块；**交付序见 `../idea/design_doc.md` §12（B14）** | import 方向 lint 规则（§1.3 矩阵） |
| P4 | HTML 片段与内联标记原样直通（零改写）；**唯一例外**：产物层图片 `src` 重写（含片段内 `<img>`，A7）——normalize.images 以重写前哈希路径集合为口径 | 往返测试（normalize 等价，§3 M04） |
| P5 | 口径唯一：normalize()、rule_id、anchor 各为单一判定口径 | 各自单测固定 |
| **P6** | **运行期 LLM 无关**：系统任何运行路径（API/CLI/渲染/导入/鉴权/巡检）**不调用任何 LLM 或远程推理服务**；`coding agent` 仅为**外部客户端**（通过 CLI/HTTP 调用本系统），非本系统的运行期依赖 | ① `import` 白名单 lint：业务代码不得引入任何推理 SDK（`openai`/`anthropic`/`transformers`/`torch`/`litellm` 等）；② 出网审计：运行期无对外 LLM 域名连接（离线测试：断网后全功能可用）；③ 依赖树审计：`uv tree` 无推理类依赖；④ 端到端测试在**无 LLM 凭据**环境运行通过 |

### 1.2 Agent Context

| 项 | 值 |
|---|---|
| 模块数量 | **11 功能模块（M01–M11）+ 1 边界（M-LR）+ 1 横切（M12 可观测性）** —— **V7 修复**：原「9 模块」为 v1.2 遗留，与 §1.3 矩阵/§2 结构/functional REQ 三处不一致，现统一；M11 属 L4 接口层（§1.3/§3 M11） |
| 依赖深度 | 最长链 M01 → M02 → M03 → M04 → M06/M07（深度 5） |
| 参考文档 | 本规范 + `../idea/design_doc.md`（设计依据）+ `../idea/clarifications.md`（B/Q 台账） |
| 编号约定 | 见 §1 开头的「编号命名空间」表（P/A/B/S/V/REQ 六套前缀） |

### 1.3 分层归属与依赖规则矩阵

%%为什么需要模型层？这个系统应该是LLM无关的%%
>
> **答复（B4）**：成立且已澄清。L1 原名「模型层」系**领域数据模型**（pydantic schema/anchor/原子类型），与 LLM 无关；本系统**整体 LLM 无关**——不调用任何 LLM API，语义检索经 M-LR 交由 LightRAG。为消歧，L1 改显示名为「**领域模型层**」（M01 标识不变，ID 稳定要求）。


| 层 | 模块 | 可见性 |
|---|---|---|
| L1 领域模型层 | M01 | 全部可见（无依赖）——**LLM 无关**：纯类型/schema/锚规则，无任何模型 API 调用 |
| L2 存储层 | M02 | 依赖 L1 |
| L3 领域服务层 | M03, M04, M05, M09 | 依赖 L1–L2 |
| L4 接口层 | M06, M07 | 依赖 L1–L3 |
| L5 前端 | M08 | 仅依赖 M07 的 OpenAPI 契约 |
| L6 边界 | M-LR | 依赖 L2/M04（导出），被集成方消费 |
| L7 鉴权横切 | M10 | 依赖 L2（users/ssh_keys/grants/sessions/nonces）；被 M06/M07 前置调用 |
| L8 可观测性横切 | M12 | 依赖 L0（AgenticLogger SDK，外部包）；被**所有模块**调用（ADR-010） |

**允许依赖（√）/禁止（×）**：

| 从 ↓ / 到 → | M01 | M02 | M03 | M04 | M05 | M09 | M06 | M07 | M08 | M-LR | M10 | M12 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| M02 | √ | — | × | × | × | × | × | × | × | × | × | √ |
| M03 | √ | √ | — | × | × | √(9A) | × | × | × | × | × | √ |

| M04 | √ | √ | × | — | × | × | × | × | × | × | × | √ |
| M05 | × | √ | × | × | — | × | × | × | × | × | × | √ |
| M09 | √ | √ | × | √(9B) | × | — | × | × | × | × | × | √ |
| M06 | √ | √ | × | √ | × | √(9A) | — | × | × | × | √(鉴权) | √ |
| M07 | √ | √ | × | √ | × | × | × | — | × | × | √(鉴权) | √ |
| M08 | × | × | × | × | × | × | × | √(HTTP) | — | × | × | × |
| M-LR | × | √ | × | √ | √(内部) | × | × | × | × | — | × | √ |
| M10 | √ | √ | × | × | × | × | × | × | × | × | — | √ |
| **M12** | × | × | × | × | × | × | × | × | × | × | × | — |

**M11 依赖声明（V7；调用路径裁决 2026-09-16）**：M11（CLI/skill）→ 依赖 **M06/M07 的 HTTP 契约** + **M10**（签名与身份）；属 L4 接口层。矩阵中不单列 M11 行（其依赖通过 M06/M07/M10 体现）。

**调用路径区分（实现裁决，解决 §3 M11「不直连 DB」与 §3 M03 的冲突）**：
| 命令类别 | 路径 | 理由 |
|---|---|---|
| **用户级操作**：`doc`/`node`/`comment`/`user`/`grant`/`render`/`diff` | **经 HTTP**（M06/M07） | 与 WebUI 享**同一鉴权/RBAC/授权口径**（P5 口径唯一），服务端逐请求判定 |
| **批量数据导入**：`import commit` | **in-process 调 M03 `run_commit`**（先 HTTP `whoami` 做角色检查） | 10k 文档批量写入经 HTTP 逐节点提交**性能不可行**；M03 的 `commit` 本就是设计内的工具函数（`WriteContext(source="importer")`） |
| `auth bootstrap` | **本地 DB 直连** | 它建立鉴权本身，此时无凭据可用 |
| `logs` | 本地 `agentic-logger` CLI 封装 | 读本地 JSONL，无服务端语义 |

**文档级软删的缺口（待集成阶段裁决）**：`docs` 表无 `deleted` 标志、M06/M07 无 `DELETE /docs/{id}`，故「文档软删」当前**无原子服务端目标**。CLI 的 `doc delete` 暂实现为**逐节点级联软删**（非原子，失败时列出已删/未删清单并不静默）。**后续选项**：为 M07 增 `DELETE /api/v1/docs/{id}`（文档级软删 + 级联，同事务）——待 it.mas/实现阶段决定。
> **M12 说明**：可观测性为**横切关注点**（非业务模块），所有模块经 `observability/logger.py` 单一适配层调用 AgenticLogger SDK（ADR-010）；M12 自身不依赖任何业务模块（保证无环）。M08 不直连 M12（前端日志经 M07 转写）。

**M05 降级说明（批注 B5）**：M05 保留实现但**不再暴露公开端点**，仅作为 M-LR 导出的内部依赖（LightRAG 增量导出需 refs 图结构）；M06 的 `/traverse`、`/search` 端点随之删除。见 ADR-008。

### 1.4 非功能需求（量化，与 B10 对齐）

%%部分文档如功能列表，应该渲染为可编辑的表格%%
>
> **处置（B6）**：已落地，见 §3 M04 `EditableTableMode` 与 §3 M07/M08 表格编辑端点。**渲染是默认只读**；仅当文档 frontmatter `editable_tables: true`（或 doc_type 在可编辑白名单）且请求方具备 editor 角色时，表格渲染为可编辑控件（回写走既有节点写端点，非自由 HTML 编辑）。

%%Webui是否可以支持飞书的多维文档%%
>
> **答复（B7）**：**不支持，明确排除**。理由：(1) 飞书多维文档（Base/bitable）是 SaaS 闭源格式，读写需飞书开放平台凭据与网络可达，与本系统「单机、私有、LLM 无关」定位冲突（B6/§1.1 P1）；(2) 其数据模型（多维表视图/字段类型）与本文档原子模型（clause/table/figure）不可无损映射，双向同步会造成权威源分裂，违反 P1；(3) 本项目已提供 schema 驱动的可编辑表格（B6），覆盖「结构化表格编辑」这一**真实需求**，无需引入外部 SaaS。**若未来需要**：作为 M-LR 式的**边界集成**（导出/导入器），不进入核心数据模型。



%%lightRAG侧语义检索不在本项目范围；%%
>
> **处置（B8）**：确认并已收窄。语义检索**不在本系统实现**；本系统只经 M-LR 提供导出接口（渲染文本 + node_id + 增量事件流）供 LightRAG 消费。§1.4 的「语义检索（联调后）P95 <5s」为**对端（LightRAG）指标**，非本系统承诺，标注已修正。


> [!TODO] 规模改为 支持10000个Agent/bot，上万份文档
>
> **处置（B9）**：已落地并按用户澄清收紧口径——「10000」为**已注册 agent 身份总额**（非并发写入者数），实际并发写入为个位至数十级；「上万份文档」为真实增长预期。量化推演：10,000 文档 × ≈1,343 原子/文档（实测 7 份语料 ≈9.4k 原子校准）≈ **13.4M 节点**，存储 20–54GB（视 content 密度）。相对原基线 ≤100k 节点提升 **134×** ⇒ 原 B10「≤100k 节点/≤500 文档」**已作废**，替换为下表；并连带触发 §4 DDL 分区策略（ADR-009）。架构选型**不变**：纯 PG 仍足够（13M 行对 PG 16 为中等量级），无需分布式。


| 指标 | 目标 | 测量口径 |

| 规模（文档） | **≥10,000 份文档**；单库节点 ≈13.4M（条款级粒度，按 1,343 原子/文档实测校准）。**验收方式（PerfBench 实测口径）**：实跑 **100 文档 / 134,500 节点 = 目标 1.00%** + 按实测节点/文档线性外推（外推值 1.345e7 与目标一致）；全量验收需**专用宿主 + ~40h**（导入吞吐 57–106 节点/s，见下「已知瓶颈」） | 库内计数（`SELECT count(*)`）；超 20M 节点触发再评估（分区/归档） |
| 规模（身份） | **≥10,000 个已注册 agent 身份**；并发写入者 ≤50（按用户澄清口径） | `users` 表计数；并发以 PG `pg_stat_activity` 活跃写事务峰值度量 |
| 存储（**nodes 内容口径**） | ≈20–54GB（13.4M 节点 × 0.5–4KB/节点） | `pg_total_relation_size` 汇总 |
| 存储（**库内总占有口径**，修正） | **≈62–70GB**（实测 5.0–5.2KB/节点 × 13.4M）——含索引/TOAST、`events` 1:1（P2 事件+实体同事务的必然结果，占 58.5%）、64 分区固定开销 | 按叶子关系（`relkind='r'`）求和 + `pg_database_size` 对账；**必须扣除 schema 固定开销**后按净密度外推（PerfBench 实测口径） |
| 点查延迟 | PG 查询 **P95 <200ms**（分区后维持） | 基准脚本 `tests/perf/`：语料全量入库后固定查询集（≥100 次）取 P95，本机 PG 16.15 |
| 渲染（分章节） | **单章节 <1s**（新增，替代原「单文档 <3s」）；整档 <3s 保留为上限 | 同基准脚本；章节 = 单个 level-1/2 子树，按 M04 `render_section()` 计时（最大文档 CXL 3.59MB） |
| 鉴权开销 | 验签 + 会话校验 P95 **<10ms**（新增） | M10 单测基准（Ed25519 验签 + PG 会话查） |
| 语义检索（联调后） | P95 <5s —— **对端 LightRAG 指标，非本系统承诺**（B8） | LightRAG 侧基准 |
| 解析 | 规则覆盖率 ≥95%；零静默丢弃 | `import stats` 输出（口径见 functional_spec REQ-M03-F01/F04） |

> **指标测量机制（ADR-010，用户要求「要有性能评估和监控机制」）**：上表所有指标均**可测可验**，测量手段三层——
> 1. **在线**：AgenticLogger 记 `dur`/`error_code`（按端点/模块聚合），`GET /api/v1/admin/metrics` 查询快照；
> 2. **离线基准**：`tests/perf/bench_{point_query,render,auth,scale,import}.py`（可复现，验收证据）；
> 3. **健康巡检**：`agenticspec stats --health`（分区/索引/膨胀/连接池/归档逾期）。
> 分层告警语义：单次 >0.8×指标 → `warn`；>指标 → `error`（`DTO_PERF_EXCEEDED`）；窗口 P95 >1.5×指标 → `critical`（附建议）。

| 监控项 | 采集点 | 存储/查询 |
|---|---|---|
| API 耗时（端点 × P50/95/99） | M06/M07 中间件 | AgenticLogger JSONL → `agenticspec logs stats` |
| 错误率（端点 × error_code） | 同上 | 同上（`--group-by error_code`） |
| 慢查询 Top-N | M02 查询包装器（> `SLOW_QUERY_MS`） | 同上 |
| 鉴权失败率 | M10 `verify_signature` | JSONL + PG `events(entity='auth')` |
| 渲染耗时（整档/章节） | M04 | JSONL |
| 导入进度/覆盖率 | M03 | JSONL |
| 容量健康（分区/膨胀/索引/归档） | M09B `perf_health` detector | `agenticspec stats --health` |

**审计与日志分离（P2 强化）**：AgenticLogger 记**运行日志**（可轮转可丢弃）；审计事件仍落 PG `events`（append-only 权威）。两者不可互替。

> **指标变更依据（B9）**：`docs`/`nodes`/`events` 按 `doc_id`/`ts` 分区（ADR-009）；写入连接池上限与 `autovacuum` 调参纳入 §5；`events` 保留策略（>24 个月归档）见 ADR-009。
%%文档的渲染通过webui，分章节分别渲染，单文档渲染延时小于1s%%
>
> **处置（B10）**：已落地。(1) 新增 M04 `render_section(doc_id, section_node_id) -> RenderResult`，按 level-1/2 子树渲染，指标 **单章节 <1s**；(2) M07 新增 `GET /api/v1/docs/{id}/sections`（章节清单）与 `GET /api/v1/docs/{id}/render?section=`（章节渲染）；(3) M08 WebUI 改为**按需分章节加载**（进入文档先取章节清单，滚动/点击时按章节拉取渲染结果），替代一次性整档渲染；(4) 整档渲染 <3s 保留为上限指标（导出/CLI 场景）。


## 1.5 文档类型与行业标准对齐（方案 C，2026-09-17）

> **背景**：用户质问「不同类型的文档要参考相应的行业标准或成熟模板，设立不同的 schema，这一点是否有遵守？」→ 核实为**主体未落实**（仅 5 个粗粒度 `doc_type` 且四条规则与 `standard` 完全相同），用户选定**方案 C** 全量落实。

**权威依据**：**`doc_type_mapping.md`**（本目录）——含完整映射表（idea.md 30+ 类型 → 5 个 doc_type）、五类差异化规则表、UCIS/vPlan 对齐方案、**验证边界声明**。

**三条硬约束**：

| # | 约束 | 理由 |
|---|---|---|
| 1 | **`doc_type` 保持 5 值**（`standard`/`lang`/`tool-manual`/`product`/`safety`）；`product` 的细分靠 **`meta.doc_subtype`** | 收敛原则：多数 idea.md 类型的**内容原子组合相同**，差异只在业务元数据；仅当原子组合确实不同才新增 `doc_type` |
| 2 | **五类规则必须实质不同** | 防退回「空壳差异化」——须有测试断言五类的 `allowed_atom_types`/`required_meta_fields` **彼此不全等** |
| 3 | **验证边界如实标注** | 仅 `standard` 有真实语料（7 份）可端到端验证；其余四类与 UCIS/vPlan **只有合成样例**，**不得声称端到端验证** |

**行业标准对齐落点**：

| idea.md 参考标准 | 落点 |
|---|---|
| DocBook `RefEntry`（§4.1） | `lang`/`tool-manual` 的必填 `command_name`/`syntax`/`tool_context` |
| NISO STS（§4.2） | `standard` 的 clause + 规范性关键词 + `table.register_field` + `figure.state_machine`（已交付） |
| UCIS / vPlan（§4.3） | 新变体 `table.coverage_matrix` + `importer/vplan.py`（导入器 + 合成样例验证） |
| 需求追溯（§4.5） | `product` 必填 `traces_to` + `refs.traces_to`（已交付机制） |
| FMEA/FTA（§4.5） | 新变体 `table.failure_mode`（`safety` 专属） |

## 2. 代码结构与模块映射

```
src/agenticspec/
├── model/          # M01（schemas.py, anchors.py, atoms.py, doc_types.py）—— 领域模型层，LLM 无关
├── store/          # M02（db.py, nodes.py, refs.py, events.py, comments.py, assets.py, docs.py）
├── importer/       # M03（parser/, rules/, cli.py, proposals.py, assets_sync.py）
├── render/         # M04（renderer.py, normalize.py, sections.py, __main__.py）
├── retrieve/       # M05（traverse.py, search.py）—— 内部实现，无公开端点（ADR-008）
├── agent_api/      # M06（router.py）
├── webui_api/      # M07（router.py）
├── m09/            # M09（engine_9a.py, quality_9b/）
├── auth/           # M10（ssh_verify.py, sessions.py, rbac.py, users.py, cli.py）—— 批注 B2/B3
├── observability/  # M12（logger.py, rid.py, metrics.py, health.py, cli.py）—— ADR-010
├── mlr/            # M-LR（export.py, stream.py）
├── mcp/            # M13（server.py：标准 MCP stdio 服务，M06/M07 契约的 shell 载体）
├── cli.py          # M11 统一 CLI 装配（import/render/auth/user/doc/node/comment/logs/stats，§9.2）
└── app.py          # FastAPI 装配（M08 静态挂载 + M10 鉴权中间件 + M12 埋点中间件）
webui/              # M08（React+TS+Vite；登录页走 SSH 挑战-响应）
skills/             # 外部 coding agent 的 skill 定义（§9.3）——**非运行期依赖**（P6）
logs/               # AgenticLogger 输出（gitignore；轮转保留，见 §5）
tests/              # 单元/集成/e2e + fixtures/ + perf/（bench_*.py，ADR-010）
alembic/            # DDL 迁移（AB4）
```

## 3. 模块接口契约

### 3.0 公共类型定义（A14）

```python
# agenticspec/model/types.py（片段）
UUID7 = UUID                     # UUIDv7：应用侧生成（时间有序）

class WriteContext(BaseModel):   # A3：一切写入的身份与来源
    actor: str                   # 非空；取值规则见 §6
    source: Literal["agent","webui","cli","importer","system"]

class NodeIn(BaseModel):
    node_id: UUID7 | None; doc_id: str; atom_type: str
    format: Literal["md","html","text"] = "md"
    ordinal: int; parent_node_id: UUID7 | None; level: int | None
    anchor: str; content: dict
class Node(NodeIn):
    node_id: UUID7; status: Literal["active","deleted"]; version: int
    created_at: datetime; updated_at: datetime

class RawFallback(BaseModel):    # 未映射块兜底（note/code）
    atom_type: Literal["note","code"]; format: Literal["html","md"]
    text: str; source_lines: tuple[int,int]
class UnmappedBlock(BaseModel):
    source_lines: tuple[int,int]; reason: str; fallback: RawFallback

class Proposal(BaseModel):
    proposal_id: str             # 稳定（doc_slug + 源行区间）
    rule_id: str; confident: bool
    source_lines: tuple[int,int]
    atom: NodeIn | RawFallback
class ParseStats(BaseModel):
    total_blocks: int; rule_covered: int; fallback: int; pending: int
class ParseResult(BaseModel):
    doc_meta: dict; proposals: list[Proposal]; unmapped: list[UnmappedBlock]; stats: ParseStats

class RefKind = Literal["traces_to","see_also","composes_from","source_ref"]
class Event(BaseModel):
    event_id: UUID7; entity: Literal["doc","node","ref","comment","schema","auth"]
    entity_id: str; op: Literal["create","update","delete","status","add","remove"]
    payload: dict; actor: str; ts: datetime
class DocTypeTarget(BaseModel):   kind: Literal["doc_type"]="doc_type"; value: str
class DocTarget(BaseModel):       kind: Literal["doc"]="doc"; value: str
GrantTarget = DocTypeTarget | DocTarget      # S5：repo scope 已删除（无数据模型支撑）
class Comment(BaseModel):
    comment_id: UUID7; node_id: UUID7; target_event_id: UUID7 | None
    body: str; state: Literal["open","resolved","orphaned"]
    author: str; version: int; ts: datetime
class NodeSnapshot(BaseModel):   # apply_events 折叠结果（A18）
    node: Node | None; history: list[Event]
class SearchHit(BaseModel):     node_id: UUID7; doc_id: str; anchor: str; score: float
class TraversalHit(BaseModel):  node_id: UUID7; doc_id: str; anchor: str; hops: int; via: list[RefKind]
class RenderResult(BaseModel):  doc_id: str; out_path: str; assets_exported: int
class CommitResult(BaseModel):  doc_id: str; nodes_created: int; refs_created: int; stats: ParseStats
class QualityReport(BaseModel): detector_id: str; violations: list[Violation]
class ExportResult(BaseModel):  out_path: str; docs: int; nodes: int
class Violation(BaseModel):     rule_id: str; path: str; message: str; fix_hint: str | None
class DocIn(BaseModel):         doc_id: str; doc_type: str; title: str; meta: dict; source_ref: str | None
class Doc(DocIn):               status: "DocStatus"; version: int; created_at: datetime; updated_at: datetime
DocStatus = Literal["draft","reviewed","approved"]
CommentState = Literal["open","resolved","orphaned"]
class AssetSyncReport(BaseModel): fetched: int; missing: list[str]; total_refs: int
class QualityScope(BaseModel):  doc_ids: list[str] | None; detectors: list[str] | None
```

### M01 内容模型

```python
ATOM_TYPES = ("clause","definition","table","figure","code","example","note","cross_ref")
ATOM_VARIANTS = ("table.register_field","figure.state_machine",
                 "table.failure_mode",            # safety 专属（FMEA/FTA，idea §4.5）
                 "table.coverage_matrix")         # product 专属（UCIS/vPlan，idea §4.3）
DOC_TYPES = ("standard","lang","tool-manual","product","safety")     # A22 取值域，**保持 5 值**（§1.5 约束 1）

class DocTypeRule:                      # M01 组合规则（P5：M03 提议 / M09A 校验的唯一输入）
    doc_type: str                       # DOC_TYPES 之一
    allowed_atom_types: tuple[str, ...]         # 基底原子（八类子集）
    required_atom_types: tuple[str, ...] = ()   # 必备原子；**可含变体名**（safety 的 table.failure_mode）
    required_meta_fields: tuple[str, ...] = ()  # meta 必填字段（差异化核心）
    allowed_atom_variants: tuple[str, ...] = () # 变体白名单；空 = 不放行任何变体（不随基底自动放行）

# 五类差异化规则（权威表见 doc_type_mapping.md §3，实现见 model/doc_types.py）：
#   standard    : 八类全 | clause | C5 十七字段                          | register_field, state_machine
#   lang        : 八类去 figure | clause | command_name/syntax/tool_context | —
#   tool-manual : lang + figure | clause | 同 lang（tool_context 必填）   | —
#   product     : 八类全 | clause | doc_subtype/traces_to/owner          | + coverage_matrix
#   safety      : 八类全 | clause + table.failure_mode | standard_ref/audit_trail | failure_mode
def is_variant_allowed(doc_type: str, atom_type: str) -> bool: ...  # 变体白名单判定（M09A `M01.doc_type.variant`）
def is_atom_allowed(doc_type: str, atom_type: str) -> bool: ...      # 基底 + 变体统一判据
def missing_required_meta(doc_type: str, meta: dict | None) -> list[str]: ...  # 必填 meta 缺口（M03/M09A）

def get_json_schema(atom_type: str) -> dict: ...                     # schemas 表缓存加载
def register_schema(atom_type: str, schema: dict, version: int, ctx: WriteContext) -> None: ...  # A16 写入路径
# 注（分层裁决 2026-09-16）：M01 不提供 validate()——校验入口统一为
# `agenticspec.m09.validate_proposal(atom_type, content)`（M03/M06/M11 直接调用）。
# 理由：M01=L1、M09=L3，M01 委托 M09A 会反转 §1.3 依赖方向（L1→L3 被禁）。
# 该行原「委托 M09A」表述为 spec 缺陷，已撤销。
def derive_text(atom_type: str, content: dict) -> str: ...           # A10/R5：生成 content.text（必填）
    """HTML 片段 → 纯文本（去标签；表格按行列序拼接单元格文本）；md/文本类原样。
       约束：M01 保证一切节点 content.text 非空（FTS 生成列与检索依赖）。"""
def upsert_term(term: str, definition_node_id: UUID7 | None, kind: Literal["glossary","normative-keyword"],
                ctx: WriteContext) -> None: ...                      # R10：terms 写入路径（M03 导入 definition 原子、M07 API、种子文件 data/terms_seed.yaml）

def make_anchor(doc_id: str, chapter_path: list[str], title: str,
                occurrence_index: int, body_digest: str) -> str:     # A1 修订
    """锚 = <doc_id>#<章节号路径>·<slug(title)>；消歧优先级：
       ① 同父路径+同标题唯一 → 无后缀；
       ② 重复 → 追加 '~' + body_digest[:8]（正文摘要，非标题）；
       ③ 正文亦相同 → 追加 '~' + occurrence_index（同级稳定计数）。
       稳定性：仅依赖文档内容与同级计数；同一源文档重复解析结果逐字节一致；
       源文档改版时按 (章节号路径, slug) 匹配 + 人工确认迁移（design_doc §5.4）。"""
```

### M02 存储层（所有写方法统一携带 `ctx: WriteContext`，A3）

```python
class Storage:
    # 读
    async def get_node(self, node_id: UUID7) -> Node: ...            # 默认过滤 status='active'（A2）
    async def get_doc_nodes(self, doc_id: str, include_deleted: bool = False) -> list[Node]: ...
    async def get_doc(self, doc_id: str) -> Doc: ...
    # 文档级写（A17）
    async def list_docs(self, status: DocStatus | None = None) -> list[Doc]: ...   # R7
    async def update_doc_status(self, doc_id: str, status: DocStatus,
                                expected_version: int, ctx: WriteContext) -> Doc: ...  # 409
    # 节点写
    async def upsert_node(self, node: NodeIn, expected_version: int | None,
                          ctx: WriteContext) -> Node: ...            # 409；写 node 事件（同事务）
    async def delete_node(self, node_id: UUID7, expected_version: int,
                          ctx: WriteContext) -> None: ...            # A2：软删 seen below
    """delete_node 语义（A2）：UPDATE nodes SET status='deleted', version+1（乐观锁校验）；
       写 node 事件 op=delete（payload 含 before snapshot）；同事务 orphan_comments(node_id)。"""
    # 引用边（A5）
    async def add_ref(self, src: UUID7, dst_doc: str, dst_node: UUID7 | None,
                      kind: RefKind, ctx: WriteContext) -> None: ... # 写 ref 事件（payload {op:add,src,dst_doc,dst_node,kind}）
    async def remove_ref(self, src: UUID7, dst_doc: str, dst_node: UUID7 | None,
                         kind: RefKind, ctx: WriteContext) -> None: ...  # 对称参数
    # 事件（A18）
    async def replay(self, entity: str, entity_id: str, upto: datetime | None = None) -> list[Event]: ...
    def apply_events(self, entity: str, events: list[Event]) -> NodeSnapshot | dict: ...  # L7：node→NodeSnapshot；doc/comment→dict；ref/schema→行集重建（规则见 §3.5）
    # 批注（A4 乐观锁）
    async def create_comment(self, node_id: UUID7, body: str,
                             expected_version: int | None, ctx: WriteContext) -> Comment: ...
    async def update_comment_state(self, comment_id: UUID7, state: CommentState,
                                   expected_version: int, ctx: WriteContext) -> Comment: ...  # 409
    async def orphan_comments(self, node_id: UUID7) -> None: ...      # delete_node 内部调用
    # 资产（A6）
    async def put_asset(self, data: bytes, mime: str, origin: str) -> str: ...  # -> asset_id(sha256)
    async def get_asset_path(self, asset_id: str) -> Path: ...        # 文件系统 content-addressed
    async def list_missing_assets(self, doc_id: str | None = None) -> list[str]: ...
```

**资产字节存储（A6）**：`assets` 表存元数据，字节落**文件系统 content-addressed 目录** `ASSET_STORE_DIR`（默认 `data/assets/<sha256[:2]>/<sha256>.<ext>`）；`assets.path` 记录相对路径；`get_asset_path` 校验存在性。读取端点见 M06/M07（§3 各表）。M03 导入接口见 `assets_sync.fetch_assets(refs, source_root) -> AssetSyncReport`。

### M03 导入解析

```python
# 接口
def parse_markdown(path: Path, doc_slug: str) -> ParseResult: ...
async def commit(result: ParseResult, ctx: WriteContext) -> CommitResult: ...   # 经 M09A -> M02 事务

# 提议持久化（A13）：工作目录 data/import_work/<doc_slug>/
#   proposals.json   解析输出（含 proposal_id）
#   review_state.json 审核状态（每 proposal：pending/accepted/rejected/amended(含修正 JSON)）
# doc_slug 定义：源文件名去 .md（如 IHI0024_AMBA_APB_spec）

# 资产同步（A6/A7：覆盖 md 引用与 HTML <img src>）
def fetch_assets(refs: list[str], source_root: Path) -> AssetSyncReport: ...

# CLI（A12 统一入口：console script `agenticspec-import` 与 `python -m agenticspec.importer` 等价）
#   parse  <src.md> [--doc-slug S]           → proposals.json
#   review <doc_slug>                        → 交互审核（更新 review_state.json）
#   commit <doc_slug> [--actor importer]     → 校验 + 入库 + 统计
#   stats  <doc_slug>                        → 规则覆盖率/兜底率/待确认条数
```

### M04 渲染引擎

```python
def render_document(doc_id: str, out_dir: Path) -> RenderResult:
    """节点树（status='active'，按 ordinal）→ Markdown：format=html 片段零改写直通；
    frontmatter 按 §6（frontmatter 映射）回写；图片（含 HTML 片段内 <img src>，A7）重写为
    assets/<sha256>.<ext> 相对路径，并从资产存储导出至 out_dir/assets/。"""
def normalize(doc_id: str) -> NormalForm: ...                  # 库侧（节点树）
def normalize_markdown(source: str | Path) -> NormalForm: ...  # 源侧（markdown 文本）
# 往返断言（REQ-M04-F01，两式并列）：(a) 解析保真 normalize(doc_id) == normalize_markdown(src)；
# (b) 渲染保真 normalize_markdown(<产物文件>) == normalize_markdown(src)（HTML 直通/内联标记/frontmatter 回写
#     的破坏只发生在渲染层，必须由 (b) 覆盖；images 以重写前哈希路径集合比较）
# 渲染入口：`agenticspec-render <doc_id>` 或 `python -m agenticspec.render`（入参为 doc_id=spec_id）
def render_section(doc_id: str, section_node_id: UUID7) -> RenderResult:
    """按 level-1/2 子树渲染单章节（B10）：取 section_node_id 及其后代（ordinal 序、
    status='active'）→ Markdown；图片重写规则与 render_document 一致；
    产物落 out_dir/sections/<anchor>.md。目标：单章节 <1s。"""

class NormalForm(BaseModel):
    headings: list[tuple[int, str]]          # (level, text)
    tables: list[TableNF]                    # TableNF(rows, cols, cells: list[list[str]])
    code_blocks: list[str]
    images: list[str]                        # 含 HTML <img> 的 src 集合（重写前哈希路径集合）
    lists: list[list[str]]
    inline_markers: list[str]
```

### M05 图遍历与检索（内部实现，无公开端点）

> [!TODO] 图便利和检索是LightRAG的业务范围，不在本项目实现；只需要给lightRAG提供接口就行
>
> **处置（B5，用户裁决）**：**保留 M05 实现但降级为内部接口**。`traverse`/`search_text` 仍实现（M-LR 增量导出需 refs 图结构），但**不在 M06/M07 暴露端点**；对外检索能力由 LightRAG 承担（本系统只提供导出接口）。见 ADR-008。


```python
KIND_RULES: dict[RefKind, tuple[Literal["up","down","both"], bool, int]] = {   # (方向, 参与多跳, 最大跳数) A19
    "traces_to": ("up", True, 2), "composes_from": ("down", True, 1),
    "see_also": ("both", True, 1), "source_ref": ("up", False, 0),
}
# 方向语义（权威定义；与 idea/design_doc §6.4 一致）：
#   up   = dst→src（反向：从被引用者出发，找「谁引用了它」）——需求追溯主链
#   down = src→dst（正向：从引用者出发，找「它引用了谁」）——文法/组合关系
#   例：A traces_to B 时，从 B 出发 2 跳可找到 A（「B 服务于哪些需求」）
#   结果不含起点自身（hops≥1）
def traverse(node_id: UUID7, hops: int = 1) -> list[TraversalHit]:
    """hops 按各 kind 的 max_hops 截断（hops=2 仅扩 traces_to）；去重保留最短路径；环截断；
    排序：跳数 → doc 序 → ordinal；默认过滤 status='deleted' 节点（L5）。"""
def search_text(q: str, limit: int = 50) -> list[SearchHit]: ...   # FTS（ADR-005），返回含 score；默认过滤 deleted（L5）
```

### M06 Agent 接口（HTTP）

**可编辑表格模式（B6/V8 修复）**：`EditableTableMode` 为 M04 渲染期的判定结果类型：

```python
class EditableTableMode(BaseModel):
    editable: bool                      # True → table 原子渲染为可编辑控件
    reason: Literal["flag_on", "doc_type_whitelist", "role_insufficient", "flag_off", "html_fragment"]
    # 判定：editable = (doc.meta.editable_tables is True OR doc.doc_type ∈ EDITABLE_DOC_TYPES)
    #                 AND caller.role ∈ {admin, editor} AND node.format != 'html'
    # html 形态（<table> 片段，含 80 处 <img>）恒为 editable=False（P4 零改写直通）
EDITABLE_DOC_TYPES: frozenset[str] = frozenset()   # 默认空；由配置扩展
def resolve_table_mode(doc: Doc, node: Node, user: User) -> EditableTableMode: ...
```

**回写端点（V8 修复，统一口径）**：编辑提交**一律**走 **`PATCH /api/v1/nodes/{node_id}/table`**（新端点，body = 行列 JSON + `expectedVersion`），由服务端转 `content` 并写 `node` 事件——**不是**「走既有节点写端点」（原表述有误，已修正）；校验用 **`expectedVersion` 乐观锁**（`nodes.version`，原「epoch 校验」为术语误用，已修正）。

| 方法/路径 | 语义 | 关键错误 |
|---|---|---|
| `GET /api/v1/nodes/{node_id}?doc_id=` | 节点读（含 version）；**doc_id 可选**——传入则分区裁剪，缺失则全分区扫（降级，ADR-009 V16） | 404 |
| `GET /api/v1/docs/{doc_id}/nodes` | 文档节点树（默认 active） | 404 |
| `POST /api/v1/nodes` | 结构化写入（NodeIn + expected_version） | 422/409 |
| `DELETE /api/v1/nodes/{node_id}?expected_version=` | **软删**（A2，写 delete 事件 + orphan 批注） | 404/409 |
| `POST /api/v1/refs` / `DELETE /api/v1/refs` | 引用边增删（body: src,dst_doc,dst_node,kind） | 404/422 |
| ~~`GET /api/v1/nodes/{node_id}/traverse?hops=`~~ | **已移除**（B5/ADR-008：图遍历属 LightRAG 业务，M05 降级为内部实现） | — |
| ~~`GET /api/v1/search?q=&limit=`~~ | **已移除**（同上；检索由 LightRAG 承担） | — |
| `GET /api/v1/docs/{doc_id}/sections` | 章节清单（level-1/2 节点，B10 分章节渲染入口） | 404 |
| `GET /api/v1/docs/{doc_id}/render?section=` | 章节渲染（省略 section → 整档；B10） | 404 |
| `GET /api/v1/assets/{asset_id}` | 资产字节流 | 404 |
| `POST /api/v1/docs/{doc_id}/render` | 触发渲染 | 404 |

**鉴权（B2/B3）**：**默认所有端点（含读）需 M10 鉴权**；**唯一豁免白名单**（S4 修复）如下——

| 豁免端点 | 理由 | 仍受约束 |
|---|---|---|
| `POST /api/v1/auth/challenge` | 登录流程起点，此时无任何凭据 | 按 IP 限流（见 §3 M10） |
| `POST /api/v1/auth/login` | 同上（提交签名换取会话） | 同上 + nonce 一次性 |
| `GET /` 与登录页静态资源（`/assets/login-*`） | 登录页自身加载所需 | 仅限白名单文件，不含业务数据 |
| `GET /healthz` | 进程存活探针（**不返回任何业务/版本信息**） | 无 |

**明确不豁免**：`/docs`、`/openapi.json`、`/redoc` 在非开发模式下**禁用**（`docs_url=None`）；`DEV_MODE=1` 时开启且仅允许 loopback。**豁免清单外端点无凭据必 401**。

**agent 路径**（每请求签名）：
- 请求头：`X-SSH-Signature`（base64）、`X-SSH-Key-Id`（公钥指纹）、`X-Timestamp`（ISO 8601, UTC, 秒级）、`X-Nonce`（≥128 位随机, base64）。
- **签名载荷（S2 修复，字节级精确）**：
```text
payload = METHOD + "\n" + RAW_PATH + "\n" + SHA256(body).hexdigest() + "\n" + TIMESTAMP + "\n" + NONCE
```
  **规范化规则（双方不得另行规范化）**：`RAW_PATH` = 请求行中路径 + `?` + query 的**原样字节**（不百分号解码、不去点段、不增删尾部斜杠）；**query string 参与签名**——篡改 query 任一参数 → 401。
- **签名编码（S11 修复）**：统一 **SSHSIG**（`ssh-keygen -Y sign` 产物），namespace 固定 `agenticspec@auth`；RSA 用 `rsa-sha2-512`（**验签先试 PSS 再回落 v1.5**——实测 ssh-keygen 输出 v1.5；签名固定 PSS）。CLI 与 WebUI 登录页共用**同一验签器**。
- **校验顺序（S3/S7 修复）**：① `X-Timestamp` 偏移 ∈ [−30s, +`SIGNATURE_MAX_SKEW_SECONDS`]（**未来偏移容忍 30s**）→ ② `X-SSH-Key-Id` 查 `ssh_keys`（active）→ ③ **验签** → ④ **验签通过后**才 INSERT nonce（未认证请求不写库）。失败：401（无/坏凭据）、403（公钥未注册或角色不足）。

**WebUI 路径**：`Cookie: agenticspec_session=<token>`（登录时经同一 SSH 挑战-响应换取，见 M10）。写入时 `WriteContext(actor=<验签所得 user_id>, source=<凭据类型>)`——**`source` 由凭据类型判定**（Cookie → `webui`；签名 → `agent`；M03 导入器 → `importer`；系统任务 → `system`），**不依赖客户端自述字段**（S14 修复：**已删除 `X-Actor` 头**，身份一律以验签结果为准）。

### M07 WebUI API

| 方法/路径 | 语义 |
|---|---|
| `GET /api/v1/docs` / `GET /api/v1/docs/{id}` | 文档列表/详情（含 version/status） |
| `GET/POST /api/v1/nodes` 等 | **复用 M06 端点**（同一实现集；source="webui" 由 X-Actor 决定；表单与 agent 共用契约，R8） |
| `GET /api/v1/schemas/{atom_type}` | **schema 端点**（表单引擎数据源；A8） |
| `GET /api/v1/events?entity=&entity_id=&since=` | 结构化 diff 数据源 |
| `GET/POST /api/v1/terms` | 术语表读写（M09B 术语校验数据源；R10/N3） |
| `GET /api/v1/events/replay?node_id=&upto=` | 版本历史（apply_events 折叠） |
| `POST /api/v1/comments` / `PATCH /api/v1/comments/{id}` | 批注创建 / `{state, expectedVersion}`（409；A4） |
| `POST /api/v1/docs/{id}/status` | `{status, expectedVersion}`（409；A17） |
| `GET /api/v1/assets/{asset_id}` | 资产读取（A6） |
| `POST /api/v1/auth/challenge` | 取登录挑战（nonce，一次性，TTL 120s；B2） |
| `POST /api/v1/auth/login` | 提交 `{keyFingerprint, nonce, signature}` → 验签通过签发会话 Cookie（httpOnly/SameSite=Lax） |
| `POST /api/v1/auth/logout` | 销毁会话 |
| `GET /api/v1/auth/me` | 当前身份（user_id/role/permissions） |
| `GET/POST /api/v1/users`、`PATCH/DELETE /api/v1/users/{id}` | 用户管理（**admin 专属**，B3/A1） |
| `POST /api/v1/users/{id}/keys` | 登记/吊销该用户 SSH 公钥 |
| `GET/POST /api/v1/roles`、`POST /api/v1/grants` | 角色与文档集级授权（**admin 专属**） |
| `PATCH /api/v1/nodes/{node_id}/table` | 表格编辑回写（B6；body 为行列 JSON + `expectedVersion`，服务端转 content；**V8 修正**：术语由误用的「epoch 校验」改为 `expected_version` 乐观锁） |

**前端契约（TS）**（A11 序列化口径：后端 pydantic `alias_generator=to_camel`，JSON 一律 camelCase）：

```ts
export type AtomType = "clause"|"definition"|"table"|"figure"|"code"|"example"|"note"|"cross_ref";
export interface NodeDTO {
  nodeId: string; docId: string; atomType: AtomType; format: "md"|"html"|"text";
  anchor: string; parentNodeId: string | null; level: number | null;
  content: unknown; version: number; status: "active"|"deleted";
}
export interface EventDTO { eventId: string; entity: "doc"|"node"|"ref"|"comment"|"schema"|"auth";
  entityId: string; op: string; payload: Record<string, unknown>; actor: string; ts: string; }
export interface DocDTO { docId: string; docType: string; title: string; status: "draft"|"reviewed"|"approved";
  version: number; updatedAt: string; }
export interface CommentDTO { commentId: string; nodeId: string; targetEventId: string | null;
  body: string; state: "open"|"resolved"|"orphaned"; author: string; version: number; ts: string; }
export interface SchemaDTO { typeName: string; version: number; jsonSchema: Record<string, unknown>; }
export interface UserDTO { userId: string; username: string; role: RoleName; status: "active"|"disabled";
  keyFingerprints: string[]; createdAt: string; }
export type RoleName = "admin"|"editor"|"reviewer"|"reader";
export interface GrantDTO { userId: string; scope: "doc_type"|"doc"|"repo"; value: string;
  permission: "read"|"write"|"review"|"admin"; }
export interface SectionDTO { nodeId: string; anchor: string; title: string; level: number;
  ordinal: number; childCount: number; }
export interface SessionDTO { userId: string; username: string; role: RoleName;
  permissions: GrantDTO[]; expiresAt: string; }
```

### M09 校验

```python
# M09A（阶段 1）—— schema 判据源：`ATOM_SCHEMAS` ∪ 变体白名单（§3 M01）
def validate_proposal(atom_type: str, content: dict, doc_type: str = "standard") -> list[Violation]: ...
def validate_write(node: NodeIn, doc_type: str = "standard") -> list[Violation]: ...
# 关键 rule_id（判据归属，勿混）：
#   M01.doc_type.atom     —— 基底原子被 doc_type 排除（恒，哪怕名字含点）
#   M01.doc_type.variant  —— 基底放行但**变体不在白名单**（方案 C 新增，2026-09-17）
#   M01.doc_type.required —— 缺少 required_atom_types（可含变体名）

# M09B（阶段 3）—— 8 个 detector（方案 C 后）
def run_quality_gate(scope: QualityScope) -> list[QualityReport]:
    """detector_id ∈ {
         broken_refs, terms, assets_missing, render_consistency, events_consistency,   # 原始 5 项
         section_range_consistency,    # M02 区间读与递归 CTE 的一致性（B-2 优化残留风险兜底）
         doc_type_schema_conformance,  # 历史数据的 doc_type 元数据合规（方案 C 新增）
         perf_health,                  # 容量巡检（M12 health()；非默认集合，需显式指定）
       }；render_consistency 消费 M04.normalize；
       events_consistency 用 M02.apply_events 重放比对当前态。"""

### M10 鉴权与用户管理（新增；批注 B1/B2/B3）

```python
# 身份与密钥（类型见 §3.0；user_id 一律 UUID7，与 DDL uuid 列一致）
class SshKey(BaseModel): key_id: str; user_id: UUID7; public_key: str
                          ; key_type: SshKeyType; added_at: datetime; revoked_at: datetime | None
SshKeyType = Literal["ssh-ed25519","rsa-sha2-512","rsa-sha2-256"]
class User(BaseModel): user_id: UUID7; username: str; role: RoleName; status: Literal["active","disabled"]
                        ; created_at: datetime; updated_at: datetime
class Grant(BaseModel): grant_id: UUID7; user_id: UUID7; scope: Literal["doc_type","doc"]
                        ; value: str; permission: Literal["read","write","review"]
                        ; granted_by: UUID7 | None; granted_at: datetime
class Session(BaseModel): session_id: UUID7; user_id: UUID7; created_at: datetime
                          ; expires_at: datetime; last_seen_at: datetime

# 签名验证（agent 路径）
def verify_signature(method: str, path: str, body: bytes, headers: SshSigHeaders) -> User:
    """Ed25519 验签。载荷 = f"{method}\n{path}\n{sha256(body).hex()}\n{ts}\n{nonce}"。
    步骤：(1) ts 偏移 ∈ [−30s, +SIGNATURE_MAX_SKEW_SECONDS]（S3：未来容忍收紧）；(2) 公钥查表（active）；
    (3) SSHSIG 验签（namespace=agenticspec@auth）；(4) **验签通过后**才 INSERT nonce（S7）。任一步失败 → AuthError(401/403)。"""

# 会话（WebUI 路径）
async def create_challenge(ip: str) -> Challenge: ...   # nonce 一次性 TTL 120s；**按 IP 限流**（S7）
async def login(key_fingerprint: str, nonce: str, signature: str) -> Session:
    """SSHSIG 验签（namespace=agenticspec@auth）；成功 → session。
    session.token = secrets.token_urlsafe(32)（**256 位 CSPRNG**，S13）；DB 仅存 SHA256(token)。"""
async def resolve_session(token: str) -> User | None:
    """**JOIN users 且 status='active'**，否则删除会话并返回 None（401）——S8：
    禁用用户/吊销密钥后，既有 WebUI 会话立即失效。会话 TTL 8h 滑动续期；
    过期清理与 nonce 清理同一任务（S15：DELETE WHERE expires_at < now()）。"""
def logout(session_id: str) -> None: ...

# RBAC（S5 修复：形式化判定，消除「OR 越权」与「上限未定义」矛盾）
ROLE_PERMISSIONS: dict[RoleName, frozenset[str]] = {
    "admin":    frozenset({"read","write","review","manage_users"}),
    "editor":   frozenset({"read","write","review"}),
    "reviewer": frozenset({"read","review"}),
    "reader":   frozenset({"read"}),
}
# 角色上限 = 该角色自身权限集（grant 不得超出）；文档集级 grant 仅在此集内**细分范围**，不扩权。
def role_permits(role: RoleName, perm: str) -> bool: ...
def grant_matches(user: User, perm: str, target: GrantTarget) -> bool: ...
def authorize(user: User, perm: str, target: GrantTarget | None) -> None:
    """判定式（S5 形式化）：
       (1) `role_permits(user.role, perm)` 必须为真 —— 角色是**硬上限**（reader + write grant 永远被拒）；
       (2) 若 target 给定且该 doc/doc_type 上存在**收窄性 grant**，则要求 `grant_matches(...)` ——
           grant 用于**限制**（如 editor 仅在 product 类型上可写），不用于扩权。
       违规 → ForbiddenError(403)，落 audit 事件。
       授予侧（POST /grants）**同时**校验 `role_permits(grantee.role, permission)`，越权 grant 在授予时即 409/422。"""

# 管理员自举（用户裁决：环境变量引导；S9 修复：语义统一）
def bootstrap_admin(public_key_path: Path) -> User:
    """**触发条件（统一语义）：不存在 status='active' 的 admin 时**执行（可重复救援）；
    否则幂等跳过。用户管理端点另有约束（S9）：
      · 不可 disable/demote/delete **自身**；
      · 不可操作**最后一个 active admin**（否则 409 并提示先指定继任者）。
    已存在 admin 且键文件变更时不自动改写（以 DB 为准）。"""
```

**权限矩阵（B3 四角色 + 文档集级授权）**：

| 角色 | 用户管理 | 文档 CRUD | 批注 | 状态审批 | 读 | 表格编辑 |
|---|---|---|---|---|---|---|
| admin | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| editor | ✗ | ✅ | ✅ | ✗ | ✅ | ✅ |
| reviewer | ✗ | ✗ | ✅ | ✅ | ✅ | ✗ |
| reader | ✗ | ✗ | ✗ | ✗ | ✅ | ✗ |


**鉴权审计（S1/S10 修复）**：所有鉴权失败（401/403）与用户/授权/密钥变更落 `events`（`entity='auth'`，**已加入 DDL CHECK 与 Event Literal**）。**失败事件的 actor 固定为 `anonymous`**（身份尚未验证），请求中自述的身份值一律记入 `claimed_*` 字段并与验证结果区分，**不得**直接写入 `user_id`/`key_fingerprint`（防污染审计，S10）。成功登录/变更事件的 actor 为验签所得真实 `user_id`。

**grant 语义（S5 修复）**：`scope ∈ {doc_type, doc}` **二选一**（`repo` 已删除——docs/nodes 无 repo 字段，属悬空概念）；`GrantTarget = DocTypeTarget(value) | DocTarget(doc_id)`（类型已补入 §3.0）。grant 为**收窄器**：角色决定「能做什么」，grant 决定「在哪些文档上」。


### M11 CLI 工具族与 Skill（新增；批注 B3/B11）

```python
# agenticspec/cli.py（Typer/argparse 装配；每命令自动签名，auth bootstrap 除外）
class SigningClient:
    """从 ~/.ssh/ 或 AGENTICSPEC_SSH_KEY 读私钥，按 §3 M06 载荷规范生成 SSHSIG 头。"""
    def request(self, method: str, path: str, body: bytes | None = None) -> Response: ...

# 命令 → 服务：CLI 不直连 DB（除 auth bootstrap），一律经 M06/M07 HTTP 端点，
# 因此 CLI 与 WebUI 享有同一鉴权/授权/RBAC 判定（P5 口径唯一）。
def cmd_import_parse(path: Path) -> ProposalBatch: ...
def cmd_import_review(slug: str, interactive: bool = True) -> ReviewResult: ...
def cmd_doc_diff(doc_id: str, from_: str | None, to: str | None) -> DiffResult: ...   # 复用 M07 REQ-M07-F06
def cmd_auth_sign(challenge: str | None = None, host: str | None = None) -> str: ...  # 登录用签名（V9/V10）
def cmd_logs(subcommand: str, **opts) -> None: ...   # 薄封装 agentic-logger CLI（ADR-010）
```

**依赖关系**：M11 → M06/M07（HTTP 契约）+ M10（签名）。**分层归属（V7）**：L4 接口层（与 M06/M07 同层，属对外交付面）。

**Skill 定义**（`skills/`，6 项）：`spec-import`/`spec-read`/`spec-write`/`spec-render`/`spec-diff`/`spec-annotations`——每项含 `name`/`description`/前置角色/底层命令四字段（可 JSON Schema 校验，V17 判据），供**外部** coding agent 消费（非运行期依赖，P6）。
**速率限制（S7 修复）**：`/auth/challenge` 与 `/auth/login` 按 IP 限流（默认 10 次/分钟，`AUTH_RATE_LIMIT_PER_MIN` 可配）；**验签失败的请求不写 nonces 表**（nonce 仅在验签通过后消费）；`auth` 失败事件按 `(ip, 5min)` 聚合计数（避免审计淹没）。

### M-LR LightRAG 边界（暂缓联调，C7）

```python
def export_package(doc_ids: list[str], out_dir: Path) -> ExportResult: ...
    """jsonl: {node_id, doc_id, anchor, text}；来自渲染文本。"""
async def change_stream(since: str | None) -> AsyncIterator[Event]: ...   # events 游标流
```

### 3.5 事件载荷与折叠规范（A18）

| entity | op | payload 形状 | 折叠规则（apply_events） |
|---|---|---|---|
| doc | create/update/status | `{field: {before, after}, …}` | 逐字段覆盖到 doc 行快照 |
| node | create/update/delete | `{field: {before, after}, …}`；delete 含 `before` 全量 | create 建快照；update 逐字段覆盖；delete 置 `status=deleted` |
| ref | add/remove | `{src, dst_doc, dst_node, kind}` | add 追加 refs 行；remove 移除对应行 |
| comment | create/update | `{field: {before, after}, …}` | 逐字段覆盖批注快照 |
| schema | create/update | `{type_name, version, diff}` | 记录 schema 版本历史 |
| auth | login/logout/fail/user_change/grant_change/key_change | `{user_id, key_fingerprint?, ip?, reason?}` | **追加**（B2：鉴权审计，不参与实体折叠，仅审计查询） |


### M12 可观测性（横切；ADR-010）

```python
# agenticspec/observability/logger.py
from agentic_logger import AgentLogger, ErrorCode

def get_logger(module: str, **ctx) -> AgentLogger:
    """模块级 logger（program="agenticspec"，command=<模块/子命令>）。
    自动注入 rid（ContextVar）与 module（M##.子域）；ctx 作为额外字段写入每行。"""

# agenticspec/observability/rid.py
def new_rid() -> str: ...                    # uuid7 短形态（8 hex）；请求/CLI 调用入口生成
def current_rid() -> str | None: ...         # ContextVar 读取（跨 async 任务传播）

# agenticspec/observability/metrics.py
class EndpointMetric(BaseModel): route: str; count: int; p50: int; p95: int; p99: int; error_rate: float
class SlowQuery(BaseModel): sql_hash: str; count: int; max_dur: int; table: str
class RenderMetric(BaseModel): section_p95: int; document_p95: int; count: int
class MetricsSnapshot(BaseModel):
    window_seconds: int; endpoints: list[EndpointMetric]; slow_queries: list[SlowQuery]
    auth_failures: int; render: RenderMetric
def snapshot(since: datetime, window: int = 3600) -> MetricsSnapshot:
    """从 AgenticLogger 查询层聚合（不引入时序库）。"""

# agenticspec/observability/health.py
class TableHealth(BaseModel): name: str; rows: int; size_bytes: int; dead_tup: int; last_autovacuum: datetime | None
class IndexHealth(BaseModel): name: str; scans: int; size_bytes: int      # scans=0 → 建议清理
class PartitionHealth(BaseModel): events_next_missing: bool; oldest_event_ts: datetime | None
class PoolHealth(BaseModel): size: int; checkedout: int; overflow: int
class HealthReport(BaseModel):
    tables: list[TableHealth]; indexes: list[IndexHealth]; partitions: PartitionHealth
    pool: PoolHealth; verdict: Literal["ok","degraded","fail"]; advice: list[str]
def health() -> HealthReport: ...            # `agenticspec stats --health` 与 M09B perf_health detector 共用
```

**错误码扩展**（`agenticspec/observability/error_codes.py`）：

| 码 | 场景 |
|---|---|
| `DTO_PERF_EXCEEDED` | 单次耗时超指标（§1.4） |
| `DTO_ANCHOR_CONFLICT` | 锚冲突（映射 `Violation.rule_id`） |
| `DTO_AUTH_REJECTED` | 鉴权拒绝（401/403） |
| `DTO_REF_BROKEN` | 引用断链（M09B `broken_refs`） |
| `DTO_PARTITION_MISSING` | 分区缺失（events 未来月份未建） |

**埋点约定**：所有对外操作（HTTP 端点、CLI 子命令、外部调用）走 `with logger.timer(module, op):` 上下文管理器，退出时自动写 `dur`；异常路径自动 `error(..., error_code=...)`。**禁止**业务代码直接 `print` 或 `import logging`（lint 强制，与 P6 验证项 ① 同机制）。

**管理端点**（M07，**admin 专属**）：

| 方法/路径 | 语义 |
|---|---|
| `GET /api/v1/admin/metrics?since=&window=` | 指标快照（`MetricsSnapshot`） |
| `GET /api/v1/admin/health` | 健康巡检（`HealthReport`） |

### M13 MCP Server（L4 接口扩展；2026-09-25 新增）

```python
# agenticspec/mcp/server.py
def build_server(client: SigningClient | None = None) -> MCPServer: ...
def run_stdio() -> None: ...          # agenticspec mcp serve（Ctrl-C 退出）
```

AgenticSpec 暴露标准 MCP（Model Context Protocol）stdio 服务，供 GigaPie/opencode 等
headless agent 以工具方式读写知识库（docs/nodes/refs/render 10 个工具）。

**非独立业务模块**（不参与 §1.2 模块计数）：M13 是 **M06/M07 HTTP 契约的 stdio 载体**——
每个工具调用复用 M11 `SigningClient` 构造一次**带 SSH 签名的 REST 请求**（method/path/body
摘要/timestamp/nonce 四头），身份判定、RBAC、grant 门控、审计全部由既有 M10 服务端完成，
无新增业务语义或存储。

**身份**（与「agent 身份 = 启动它的人类用户」同一模型，ADR-007 B2）：签名私钥 = 本进程
`AGENTICSPEC_SSH_KEY` → `~/.ssh/id_ed25519` → `~/.ssh/id_rsa`；bot 需独立身份时给 bot
专属密钥并注册账号，启动时环境变量指向它即可。base URL 走 `AGENTICSPEC_API_URL`（缺省
`http://127.0.0.1:8787`）。

**工具→端点映射**（全部走签名请求）：

| 工具 | 端点 |
|---|---|
| `docs_list(status?)` | `GET /api/v1/docs` |
| `docs_get(docId)` | `GET /api/v1/docs/{id}` |
| `docs_sections(docId)` | `GET /api/v1/docs/{id}/sections` |
| `docs_render(docId, section?)` | `GET /api/v1/docs/{id}/render` |
| `nodes_list(docId)` | `GET /api/v1/docs/{id}/nodes` |
| `nodes_get(nodeId, docId?)` | `GET /api/v1/nodes/{id}` |
| `nodes_write(body)` | `POST /api/v1/nodes` |
| `nodes_delete(nodeId, expectedVersion)` | `DELETE /api/v1/nodes/{id}` |
| `refs_write(body)` / `refs_remove(body)` | `POST/DELETE /api/v1/refs` |

**错误语义**：SigningClient 的 401/403/404/409/422 指引（含登记/授权命令）经
`ToolError` 透传给 MCP 客户端（协议层以工具错误呈现），agent 可据指引自修复重试。

## 4. 数据库 DDL（PostgreSQL 16，database `agenticspec`；v1.3）

```sql
CREATE TABLE docs (
  doc_id     text PRIMARY KEY,                -- SPEC-*（映射见 §6 frontmatter 映射表）
  doc_type   text NOT NULL CHECK (doc_type IN ('standard','lang','tool-manual','product','safety')),
  title      text NOT NULL,
  meta       jsonb NOT NULL DEFAULT '{}',
  source_ref text,
  status     text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','reviewed','approved')),
  version    bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE nodes (
  node_id        uuid PRIMARY KEY,
  doc_id         text NOT NULL REFERENCES docs(doc_id),
  atom_type      text NOT NULL,
  format         text NOT NULL DEFAULT 'md' CHECK (format IN ('md','html','text')),
  ordinal        integer NOT NULL,
  parent_node_id uuid REFERENCES nodes(node_id) ON DELETE SET NULL,
  level          smallint,
  anchor         text NOT NULL,
  content        jsonb NOT NULL,             -- 约定：content.text 必填（检索源，A10）
  status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active','deleted')),  -- A2 软删
  version        bigint NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (doc_id, anchor)
);
CREATE INDEX idx_nodes_doc_ordinal ON nodes (doc_id, ordinal);
CREATE INDEX idx_nodes_parent      ON nodes (parent_node_id);
-- idx_nodes_content_gin 已移除（ADR-009：13M 行下 write amplification 不划算，且无对应访问模式）
ALTER TABLE nodes ADD COLUMN text_fts tsvector
  GENERATED ALWAYS AS (to_tsvector('english', coalesce(content->>'text',''))) STORED;   -- A10
CREATE INDEX idx_nodes_fts ON nodes USING gin (text_fts);  -- 分区局部（ADR-009 §2；每分区并行建）

CREATE TABLE refs (                              -- A5/R1 修订：代理主键 + NULL 参与唯一
  ref_id      uuid PRIMARY KEY,
  src_node_id uuid NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,
  dst_doc_id  text NOT NULL,
  dst_node_id uuid REFERENCES nodes(node_id) ON DELETE SET NULL,
  kind        text NOT NULL CHECK (kind IN ('traces_to','see_also','composes_from','source_ref'))
);
ALTER TABLE refs ADD CONSTRAINT refs_unique UNIQUE NULLS NOT DISTINCT
  (src_node_id, dst_doc_id, dst_node_id, kind);  -- PG15+：NULL 参与唯一性（文档级引用 dst_node_id IS NULL 合法）
CREATE INDEX idx_refs_dst ON refs (dst_doc_id, dst_node_id);
-- 外部叶引用：dst_doc_id 约定 'EXT:<uri>'（kind=source_ref）

CREATE TABLE events (                            -- append-only
  event_id  uuid PRIMARY KEY,
  entity    text NOT NULL CHECK (entity IN ('doc','node','ref','comment','schema','auth')),  -- S1：'auth' 为审计事件（不参与实体折叠）
  entity_id text NOT NULL,
  op        text NOT NULL,
  payload   jsonb NOT NULL,
  actor     text NOT NULL,                       -- 取值规则 §6（A3）
  ts        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_events_entity ON events (entity, entity_id, ts);
CREATE INDEX idx_events_ts     ON events (ts);

CREATE TABLE comments (
  comment_id      uuid PRIMARY KEY,
  node_id         uuid NOT NULL REFERENCES nodes(node_id),   -- 软删方案下无需级联（A2）
  target_event_id uuid REFERENCES events(event_id),
  body            text NOT NULL,
  state           text NOT NULL DEFAULT 'open' CHECK (state IN ('open','resolved','orphaned')),
  author          text NOT NULL,
  version         bigint NOT NULL DEFAULT 1,                 -- A4
  ts              timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_comments_node ON comments (node_id, state);

CREATE TABLE schemas (
  type_name   text NOT NULL,
  json_schema jsonb NOT NULL,
  version     integer NOT NULL DEFAULT 1,
  PRIMARY KEY (type_name, version)
);

CREATE TABLE assets (
  asset_id text PRIMARY KEY,                   -- sha256 hex
  mime     text NOT NULL,
  bytes    bigint NOT NULL,
  origin   text,
  path     text NOT NULL                       -- 相对 ASSET_STORE_DIR（A6）
);

CREATE TABLE terms (
  term               text PRIMARY KEY,
  definition_node_id uuid REFERENCES nodes(node_id) ON DELETE SET NULL,
  kind               text NOT NULL CHECK (kind IN ('glossary','normative-keyword'))
);

-- ============ 鉴权与用户（M10；批注 B1/B2/B3）============
CREATE TABLE users (
  user_id    uuid PRIMARY KEY,
  username   text NOT NULL UNIQUE,
  role       text NOT NULL CHECK (role IN ('admin','editor','reviewer','reader')),
  status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ssh_keys (
  key_id      text PRIMARY KEY,                -- SHA256 指纹（base64，与 ssh-keygen -lf 一致）
  user_id     uuid NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  public_key  text NOT NULL,                   -- 完整 authorized_keys 行
  key_type    text NOT NULL CHECK (key_type IN ('ssh-ed25519','rsa-sha2-512','rsa-sha2-256')),
  added_at    timestamptz NOT NULL DEFAULT now(),
  revoked_at  timestamptz,                     -- 吊销保留行（审计）
  UNIQUE (user_id, key_id)
);
CREATE INDEX idx_ssh_keys_user ON ssh_keys (user_id) WHERE revoked_at IS NULL;

CREATE TABLE grants (                          -- 文档集级授权（B3；S5：scope 二选一，repo 已删）
  grant_id   uuid PRIMARY KEY,
  user_id    uuid NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  scope      text NOT NULL CHECK (scope IN ('doc_type','doc')),
  value      text NOT NULL,                    -- doc_type 值 或 doc_id
  permission text NOT NULL CHECK (permission IN ('read','write','review')),  -- S5：无 'admin'（不可经由 grant 提权）
  granted_by uuid REFERENCES users(user_id),
  granted_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, scope, value, permission)
);

CREATE TABLE sessions (
  session_id   uuid PRIMARY KEY,
  user_id      uuid NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  token_hash   text NOT NULL UNIQUE,           -- SHA256(secrets.token_urlsafe(32))；S13：256 位 CSPRNG，明文仅存 Cookie
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,           -- 默认 now()+8h，活动时滑动续期
  last_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_sessions_expiry ON sessions (expires_at);   -- S15：清理任务 DELETE WHERE expires_at < now()

CREATE TABLE nonces (                          -- 签名重放防护（B2/S3/S7）
  nonce     text PRIMARY KEY,
  user_id   uuid REFERENCES users(user_id) ON DELETE CASCADE,
  seen_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_nonces_seen ON nonces (seen_at);   -- S3：清理 TTL = max(2×SIGNATURE_MAX_SKEW_SECONDS, 600s) ≥ 时间窗
-- S7：nonce 仅在**验签通过后**INSERT（未认证请求不写库）

```

### 4.2 分区策略（ADR-009，批注 B9）——**须先读本节**：`nodes`/`events` 的实际 DDL 受此约束（PK 含分区键、FK 降级）

```sql
-- 规模：≥10,000 文档 / ≈13.4M 节点 / 20–54GB
-- nodes 按 doc_id HASH 分区（64 个），events 按 ts RANGE 分区（按月）
CREATE TABLE nodes (...) PARTITION BY HASH (doc_id);
DO $$ BEGIN
  FOR i IN 0..63 LOOP
    EXECUTE format('CREATE TABLE nodes_p%s PARTITION OF nodes FOR VALUES WITH (MODULUS 64, REMAINDER %s)', i, i);
  END LOOP;
END $$;

CREATE TABLE events (...) PARTITION BY RANGE (ts);   -- 每月一个分区，pg_partman 或自研定时任务
-- 注：UNIQUE/PK 必须包含分区键 ⇒ events PK 改 (event_id, ts)；nodes 需 (node_id, doc_id)
-- 外键：完整降级清单见 ADR-009 §1（nodes 自引用 / refs×2 / comments×2 / terms 共 6 处）；
--      **主键调整**：nodes PK → (node_id, doc_id)，events PK → (event_id, ts)
```

### 4.3 DB 角色与权限（A15）

**⚠️ 分区化修正（实现裁决 2026-09-16，M02 实测发现）**：下方字面写法在**分区化后不成立**——分区各自持有独立 ACL，且 `ALTER DEFAULT PRIVILEGES` 会把 U/D 授给**未来**的 events 月分区，append-only 随时间失效。**权威实现**：

```sql
-- 属主：agenticspec（database owner，建库时创建）
CREATE ROLE agenticspec LOGIN PASSWORD '…';             -- 属主角色（alembic 迁移使用）
CREATE ROLE agenticspec_app LOGIN PASSWORD '…';         -- 应用连接角色（最小权限）
GRANT CONNECT ON DATABASE agenticspec TO agenticspec_app;
GRANT USAGE ON SCHEMA public TO agenticspec_app;

-- (1) 可变表：S/I/U/D 全授（docs/nodes/refs/comments/schemas/assets/terms/users/ssh_keys/grants/sessions/nonces）
GRANT SELECT, INSERT, UPDATE, DELETE ON <每个 MUTABLE_TABLE> TO agenticspec_app;

-- (2) events（含**全部分区**与 default 分区）：仅 S/I，显式 REVOKE U/D/TRUNCATE
GRANT SELECT, INSERT ON events TO agenticspec_app;
REVOKE UPDATE, DELETE, TRUNCATE ON events FROM agenticspec_app;
-- 对 events 的每个分区子表（events_202609…events_default）逐一执行同样的 S/I + REVOKE
-- 原因：分区持有独立 ACL，仅授父表不覆盖子表

-- (3) 默认权限：**只授 S/I**（未来新建的 events 月分区自动保持 append-only）
ALTER DEFAULT PRIVILEGES FOR ROLE agenticspec IN SCHEMA public
  GRANT SELECT, INSERT ON TABLES TO agenticspec_app;
-- 未来若新增可变表，需在新 revision 中显式补授 U/D

GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO agenticspec_app;
```

**校验方式**：集成测试断言 app 角色对 events 执行 UPDATE/DELETE 报错（M02 已实现，见 `tests/integration/test_store_crud.py`）。

#### 4.3.1 应用层 RBAC（M10，批注 B1/B2/B3）

见 §3 M10「权限矩阵」。DB 层仅区分属主（迁移）与应用（最小权限）；用户级权限（四角色 + 文档集级 grant）由 **M10 应用层**强制，落 `users`/`grants` 表（§4）。

**双层防护**：DB 角色防「应用被攻破后越权访问他库」；应用 RBAC 防「合法连接内越权操作」。二者不可互相替代。

**残余风险声明（S16）**：应用进程一旦被攻破（SQL 注入/RCE），攻击者经同一 `agenticspec_app` 连接可**全量读写身份四表**（`users`/`ssh_keys`/`grants`/`sessions`）并伪造身份——DB 层**无 RLS**，对此无约束。**这是已接受的残余风险**（单机自包含、无多租户需求）。收紧手段（择一，暂不实施）：① 身份四表启用 PG RLS；② 用户管理 API 走独立最小权限连接角色。**触发升级条件**：系统对外暴露或承载真实多用户生产数据时，须先实施 ① 或 ②。

## 5. 部署与运行（AB1/AB2/B15）

**TLS 与 CSRF（S6 修复）**：
- **对外监听（非 `127.0.0.1`）必须经 TLS 反向代理终止**，此时会话 Cookie 强制 `Secure`；
- **无 TLS 时仅允许 loopback 绑定**（明文 HTTP 下会话 Cookie 可被嗅探劫持，最长 8h）；
- CSRF 立场：依赖 `SameSite=Lax` + **状态变更端点仅接受 `application/json`**（拒绝表单编码跨站提交）。


```
systemd --user: agenticspec-api.service
  ExecStart: uv run agenticspec-api --host 127.0.0.1 --port 8787   # 默认 loopback（安全默认）
  Environment: DATABASE_URL=postgresql+asyncpg://agenticspec_app@127.0.0.1:5432/agenticspec
               ASSET_STORE_DIR=/home/lxx/wrk/AgenticSpec/data/assets
               IMPORT_WORK_DIR=/home/lxx/wrk/AgenticSpec/data/import_work
               RENDER_OUT_DIR=/home/lxx/wrk/AgenticSpec/build/rendered
               TERMS_SEED=/home/lxx/wrk/AgenticSpec/data/terms_seed.yaml（规范性关键词种子，随 migrate 载入）
               ADMIN_SSH_PUBKEY_FILE=/home/lxx/wrk/AgenticSpec/data/admin_keys/admin.pub（B2/M10 管理员自举）
               SESSION_TTL_HOURS=8（WebUI 会话时长，滑动续期）
               SIGNATURE_MAX_SKEW_SECONDS=300（签名时间窗，B2）
  监听: --host 0.0.0.0（**鉴权后**方可对外；无 users 表则 fail-closed，见 ADR-007）
  静态托管: FastAPI mount / -> webui/dist（AB2；登录页走 SSH 挑战-响应）
开发期: Vite devserver (5173) -> proxy /api -> 127.0.0.1:8787
测试库: agenticspec_test（AB3，可重建；同角色授权）
规模调优（ADR-009）: shared_buffers=8GB、work_mem=64MB、max_connections=200
                     应用池 pool_size=20/max_overflow=10；autovacuum scale_factor=0.05（nodes/events）
                     分区维护：nodes HASH(64)、events RANGE(月)；新分区由定时任务或 pg_partman 创建
可观测性（ADR-010）:
  AgenticLogger: program="agenticspec"，输出 logs/<module>_<command>_<ts>.jsonl
  日志轮转: 按天/按大小（LOG_RETENTION_DAYS=30、LOG_MAX_MB=500）→ 超出归档至 logs/archive/
  SLOW_QUERY_MS=200（M02 查询包装器 warn 阈值，与 §1.4 点查指标对齐）
  指标端点: GET /api/v1/admin/metrics、GET /api/v1/admin/health（admin 专属）
  基准套件: uv run pytest tests/perf/ -m perf --benchmark-json=build/perf.json
  注意: 日志为运行态（可轮转可丢弃）；**审计权威源仍是 PG `events` 表**（P2/P6）
```

## 6. 横切关注点

| 关注点 | 约定 |
|---|---|
| 身份与鉴权（B2/B3） | **全端点鉴权**（含读）：agent 走 SSH 签名（Ed25519，每请求），WebUI 走会话 Cookie（SSH 挑战-响应换取）。验签身份写入 `WriteContext(actor=<user_id>, source="agent"\|"webui")`；`X-Actor` 必须与验签身份一致（不一致 → 403）。RBAC 四角色 + 文档集级 grant（§3 M10、ADR-007） |
| 序列化（A11） | pydantic `alias_generator=to_camel`；HTTP JSON 一律 camelCase；DB 与 Python 内部 snake_case |
| 日志（ADR-010） | **AgenticLogger SDK**（AGENTS.md 强制）：`AgentLogger(program="agenticspec", command=<模块>)`；字段 `module`(M##.子域)/`rid`(请求追踪)/`dur`(ms)/`error_code`(DTO_*)/`doc_id`；HTTPS 端点与 CLI 均经 `observability/logger.py` 单一适配层。**禁止**业务代码直用 `print`/`logging`。**日志 ≠ 审计**：运行日志可轮转丢弃，审计事件落 `events` 表（append-only） |
| 可观测性边界（P6） | 系统运行**不依赖 LLM**：AgenticLogger 为确定性本地库（无网络/无推理）；日志的 agent 可读性是**可选优势**，非运行期依赖 |
| 错误 | ConflictError→409、ValidationError→422、NotFound→404；Violation 结构统一 |
| ID | 应用侧 UUIDv7（时间有序）；`doc_id` 采用 `SPEC-*` 映射（A22，映射表见 §6） |
| 时间 | UTC（timestamptz）；展示本地化 |
| 配置 | 环境变量（§5 清单）；默认值指向仓库 `data/`、`build/`（gitignore） |

**frontmatter → docs 映射（A22，C5 十七字段，含 spec 专属 4 项）**：`title→title`；`spec_id→doc_id`；**`spec_type→doc_type`（经 `doc_type_mapping.md` §2 映射层归一：支持 5 个 doc_type 值 / 映射表 slug / 英文别名，大小写与空白宽松；`product` 大类细分落 `meta.doc_subtype`，见 §1.5）**；`spec_org`/`spec_revision`/`source`/`converted_*`/`reviewed_*`/`ingested_at`/`status`（approved→approved 等）→ `meta` JSONB 全量保真 + `source_ref→source`；`type/purpose/audience/direction/version/section_meta` → `meta`。必填校验：C5 十七字段（title/type/purpose/audience/direction/status/version/section_meta/spec_id/spec_type/spec_org/spec_revision/source/converted_by/converted_at/reviewed_by/reviewed_at）。 **类型差异化的 meta 必填**（`doc_type_mapping.md` §3）另计：`lang`/`tool-manual` 需 `command_name`/`syntax`/`tool_context`；`product` 需 `doc_subtype`/`traces_to`/`owner`（`doc_subtype=verification-plan` 时另需 `verification_plan_format`）；`safety` 需 `standard_ref`/`audit_trail`。

## 6.2 已知瓶颈（PerfBench 实测发现，待 it.mas 裁决）

| # | 瓶颈 | 实测证据 | 影响 | 建议 |
|---|---|---|---|---|
| ~~**B-1**~~ **已修复** | **导入吞吐**（原：逐节点事务 57.6 节点/s → 13.4M 需 35–40h） | **修复后实测**：JEDEC 722 节点 0.39s = **1,828 节点/s**；PCIe 3,428 节点 2.01s = **1,706 节点/s**。**提升 31.7×** → 13.4M 节点 **≈2.0–2.2 小时**（原 35–40h） | 10k 文档导入**已工程可行** | **已修**：M03 `commit_document_bulk`（`asyncpg.copy_records_to_table`，每批 5k 行一事务）+ CLI `import commit --bulk [--bulk-mode online\|initial_load]`。**语义 A/B 已验证**：节点行逐字段一致 + 事件 `(entity,op)` 计数与锚集合全等 + 幂等（二次 `nodes_created=0`）+ P2（批内同事务）。**注**：模式②（先 COPY 再并行建索引，ADR-009 §2）**未自动实现**（涉 DDL 与并发，属装载后运维编排，docstring 已注明） |
| ~~**B-2**~~ **已修复** | **`render_section` 是 O(全文) 而非 O(章节)** | 修复前 `get_doc_nodes` 占章节渲染 **30–87%**（PCIe 77ms/258ms；CXL 99ms/114ms） | 章节耗时随**文档**而非章节规模劣化 | **已修**：M02 新增 `get_section_nodes`（O(子树) 区间扫）+ `get_subtree`（递归 CTE，语义权威）+ `get_asset_paths`（消 N+1，语料 1,099 处引用）；M04 切换后复杂度 O(全档)→O(子树)。**遗留风险**：区间法依赖「ordinal=文档序且子树连续」不变量，**漏收**无法自检 → 已派 M09 新增 `section_range_consistency` 抽样 detector 兜底。

> **detector 设计的教训（M02 发现，值得记录）**：detector **不能**比较「公开接口 vs 权威路径」——因公开接口 `get_section_nodes` 对可检出违规会**自愈回退**到 CTE，比较结果**恒等**，反而**掩盖**了「多收」方向的脏数据。正确做法是 M02 提供的 **`section_range_diff`**（绕开自愈，返回区间法**原始**结果与 CTE 的差异：`first_diff_index`/`missing_in_interval`/`extra_in_interval`/`interval_self_check`），三态语义 `True`/`False`/`None`（`None` = 不可判定，跳过而非报错）。**推广**：任何带自愈/回退的实现，其正确性检测必须走「绕开回退的原始路径」，否则检测与自愈互相抵消。 |

**B-2 修复实测（M04，真实语料）**：

| 文档 | 全档/章节节点 | 全档读 | 资产取路径 | 章节 e2e | 修复前估值 |
|---|---|---|---|---|---|
| PCIe | 3,428 / 1,369 | 86.5 → **35.3ms** | **188.8ms（302 次点查）→ 1.6ms** | ≈283.8 → **45.4ms** | — |
| CXL | 4,822 / 1,110 | 108.2 → **29.4ms** | 4.5 → **0.8ms** | ≈120.2 → **37.8ms** | — |
| AMBA | 72 / 31 | 2.6 → 2.3ms | 4.5 → 0.8ms | ≈8.6 → **4.7ms** | — |

**结论修正**：**资产取路径的 N+1 才是图片密集文档的最大单项开销**（PCIe 302 次点查 = 188.8ms，比全档读还贵），非 PerfBench 原归因的 `get_doc_nodes`。`get_asset_paths` 批量接口（单条 `= ANY(...)` + 一次 stat）是本轮**最大单项收益**（−99%）。图片密集（PCIe/CXL 类规范）是**本项目主要场景**，故此项非边缘优化。

**等价性验证方法（可推广）**：不只是「产物哈希一致」，而是「新旧节点序列**逐元素全字段指纹一致**（node_id/ordinal/status/anchor/level/atom_type/format/content）+ `body_text` sha256 一致」——因渲染是节点序列的**纯函数**，这**证明**了产物不变（而非仅观测到不变）。 |
| **B-3** | **鉴权余量依赖宿主负载** | 安静窗口 P95 3.87–4.31ms；与并发集成套件同 PG 实例时 8.04/4.97ms；纯 Ed25519 仅 0.119ms → 成本在 2 次 PG 查表 + nonce 事务提交 + 日志落盘 | 并发场景余量降低 | 若需更多余量：nonce 落库改批量/异步（需权衡 S7 防重放语义） |

## 6.1 已知限制（实现阶段发现，待 it.mas 裁决）

| # | 限制 | 影响 | 处置 | 引入方 |
|---|---|---|---|---|
| **L-1** | `figure`/`cross_ref` 原子**无 `fragment` 字段**（M01 schema `additionalProperties:false`），导入期无法承载原文，渲染期只能**合成** `![](assets/<sha>.ext)` / `[text](target)` | 视觉无差异；但 figure 行尾的 markdown 硬换行空格（源 `![](...)  `）**丢失**；整档正文不再逐字节等于源 | **本轮不修**（改动牵动 M01/M03/M04 三方 + 锚规则）。`derive_text` 仍从源块提取文本，**检索不受影响**。P4 证据改用**逐节点覆盖**（AMBA 72/72、CXL 4,822/4,822 节点的渲染文本均为产物逐字节子串）+ `<table>` 片段逐字节（1,243/1,243）+ 两式往返 | M04 实测 |
| **L-2** | 块序/块边界与源不同（M03 按原子模型重组：clause 合并标题+段落、表格/图/代码抽离为独立原子）；块间空行归一（CXL +975 行） | 「整档正文逐字节等于源」**不可达**（设计使然，非缺陷） | 接受。P4 的真实约束是「**每块原文逐字节保留**」（M03 已全量证明），非「整档连续」 | M03/M04 |
| **L-3** | `docs` 无 `deleted` 标志，M06/M07 无 `DELETE /docs/{id}` | 「文档软删」无**原子**服务端目标；CLI `doc delete` 实现为逐节点级联（非原子） | 待裁决：为 M07 增文档级软删端点（同事务级联） | M11 发现 |
| **L-4** | **`schemas` 表与 `ATOM_SCHEMAS` 是两套来源**：`POST /schemas` 注册新 atom_type 会使 M07 端点与 M08 表单引擎看到它（**表单自动出现** ✓），但 M09A 的判据源是代码内 `ATOM_SCHEMAS`，故新类型**写入被拒**（`M01.doc_type.atom`） | REQ-M08-F01「零手写 UI」的**表单侧达成**，「端到端可写入新类型」**未达成** | **记录为已知限制**（本轮不修）。完整合并需 M01（`is_atom_allowed`）+ M09A（`validate_proposal` 动态加载）+ M07（`/schemas`）+ M04 四模块联动，且需 schema 加载/缓存/版本演进语义（§3.5 有 `schema` 事件但复审口径未定）。**现状**：8 类原子 + 4 变体覆盖现有 7 份语料 100% 形态（M03 实测 10,271 节点零未覆盖）。**升级触发（已触发）**：§1.5 方案 C（2026-09-17）引入了非 `standard` doc_type 差异化规则与 2 个新变体（`table.failure_mode`/`table.coverage_matrix`），两套来源的合并仍待 it.mas 裁决；本轮只扩大**代码种子**（新增原子/变体须同时改 `ATOM_SCHEMAS` 与 `DOC_TYPE_RULES`） | M08 实测发现 |

## 7. 与 idea 层的偏差声明

**结论：本版（v1.3）为方向性变更，需回写 idea 层**。批注 B1/B2/B3/B6/B9/B10/B11 改变了原设计的假设与范围：
1. **B6「单机、单用户、无鉴权」作废** → 全端点 SSH 鉴权 + WebUI 会话 + RBAC（ADR-007）
2. **B10「≤100k 节点/≤500 文档」作废** → ≥10,000 文档/≈13.4M 节点（ADR-009）
3. **M05 检索能力外移** → 降级为 M-LR 内部接口，语义检索归 LightRAG（ADR-008）
4. **新增交付物**：M10 鉴权模块、CLI 工具族（§9.2）、coding agent skill 清单（§9.3）
5. **渲染粒度**：整档 → 分章节（<1s）

回写项见 §7.2。A1/A7/A20 的既有回写（§7.1）保持有效。

### 7.1 回写记录

| 项 | idea 文档 | 修订 |
|---|---|---|
| A1 | design_doc §5.4 / ADR-006 | 锚消歧改为「正文摘要 + 同级序号」；稳定性表述改「仅依赖文档内容与同级计数」 |
| A7 | design_doc §5.2 | 图片引用数更正：md 形式 1,019 + HTML `<img>` 80（合计 1,099）；策略覆盖 HTML 内 img |
| A20 | functional_specification（本包） | 判据细化：goldenset 文件、perf 脚本、e2e 动作 |

### 7.2 批注触发的 idea 回写（v1.3）

| 项 | idea 文档 | 修订 |
|---|---|---|
| B6 | `clarifications.md` §2 | **作废**，替换为「SSH 公钥鉴权 + RBAC（详见 ADR-007）」 |
| B10 | `clarifications.md` §2 | **作废**，替换为「≥10,000 文档 / ≈13.4M 节点 / 10,000 身份（详见 ADR-009）」 |
| §1 目标 | `design_doc.md` | 规模目标与鉴权需求同步（P-表中的「检索与多跳推理」改注为 LightRAG 归属） |
| §2 范围 | `design_doc.md` | 「部署形态：单机、单用户、无鉴权」→ 「单机（可多用户）、SSH 鉴权、RBAC」 |
| §9 交付物 | `design_doc.md` | 新增 M10、CLI 工具族、skill 清单 |

## 8. 批注处置表（B1–B11）

| # | 批注位置 | 原文摘要 | 处置 | 落点 |
|---|---|---|---|---|
| B1 | arch L24 | 增加 webui 模块，用户只能通过 webui 对文档做 CRUD 及批注 | 修订为**权限主体分离**：人类经 WebUI（M07/M08），agent 经 CLI/skill/HTTP（M06）——两者不互斥，均由 M10 鉴权 | §1.3/§3 M06/M07/M10、§9 |
| B2 | arch L26 | agent 写入鉴权，用启动 agent 的人类用户 SSH 公钥鉴定 | 采纳并扩展为**全体端点**（用户确认）：Ed25519 签名 + nonce 防重放 + 时间窗 | §3 M10、§4 DDL、ADR-007 |
| B3 | arch L32 | 提供 CLI 和 skill 供 coding agent 调用 | 采纳：CLI 工具族（§9.2）+ skill 清单（§9.3） | §9 |
| B4 | arch L56 | 为什么需要模型层？系统应该 LLM 无关 | 澄清：L1 为**领域模型层**（非 LLM），系统整体 LLM 无关 | §1.3 |
| B5 | arch L304 | 图遍历和检索属 LightRAG 业务，只提供接口 | 采纳（用户裁决）：M05 保留实现但**降级为内部接口**，删 2 个公开端点 | §1.3/§3 M05/M06、ADR-008 |
| B6 | arch L84 | 部分文档（如功能列表）应渲染为可编辑表格 | 采纳：`EditableTableMode` + `PATCH /nodes/{id}/table`（editor 角色 + frontmatter 开关） | §3 M04/M07 |
| B7 | arch L86 | WebUI 是否支持飞书多维文档 | **明确排除**（SaaS 闭源、模型不可无损映射、违反 P1）；真实需求由 B6 覆盖 | §1.4 |
| B8 | arch L90 | lightRAG 语义检索不在本项目范围 | 确认：本系统只提供导出接口；§1.4 该指标改注为对端指标 | §1.4/§3 M-LR |
| B9 | arch L93 | 规模改为支持 10000 Agent/bot、上万份文档 | 采纳并量化：身份 10,000（非并发）+ 文档 10,000 ≈13.4M 节点；触发分区 | §1.4、§4.4、ADR-009 |
| B10 | arch L104 | 渲染经 webui 分章节，单文档 <1s | 采纳：新增 `render_section()`、章节端点、WebUI 按需加载；指标改**单章节 <1s** | §1.4/§3 M04/M07 |
| B11 | func L26/29 | 文档版本管理 + diff；skill/CLI 提供导入/删除/修改/读取 + 专用 skill 调取人类标注 | 采纳：新增 REQ-M10-*、REQ-M11-*（CLI/skill）、REQ-M07-F06（doc diff）；版本管理已由 events 重放支持，补 API 与 skill | functional §功能列表与详细说明 |

**批注原文保留**：所有 `> [!TODO]` / `%%...%%` 块均保留原位并在其下追加处置标注（评审要求：不得删除或「清理」）。

## 9. CLI 与 Skill（批注 B3/B11）

### 9.1 鉴权模型总览（B1/B2/B3）

```
┌──────────────────────────────────────────────────────────────┐
│ 身份根：SSH 公钥（Ed25519）→ users 表（user_id, role, status）  │
└──────────────────────────────────────────────────────────────┘
        │                                  │
 ┌──────┴───────┐                  ┌───────┴────────┐
 │ agent 路径    │                  │ 人类路径        │
 │ 每请求签名     │                  │ WebUI 会话      │
 │ （无状态）     │                  │ （挑战-响应登录）│
 └──────────────┘                  └────────────────┘
        │                                  │
 X-SSH-Signature                      Cookie: agenticspec_session
 X-SSH-Key-Id/X-Timestamp/X-Nonce      → M10 resolve_session()
        │                                  │
        └───────────────┬──────────────────┘
                        ▼
            M10 verify_signature() / resolve_session()
                        ▼
                User + Role + Grants
                        ▼
        authorize(user, perm, target)  ← RBAC 四角色 + 文档集级 grant
                        ▼
                M06 / M07 业务处理
```

**权限主体分离（B1/B3）**：
- **人类操作者** → WebUI（M08）+ WebUI API（M07）：文档 CRUD、批注、状态审批、用户管理（admin 专属）；
- **coding agent** → CLI（§9.2）+ skill（§9.3）+ HTTP（M06）：结构化读写、导入、lint 闭环；
- 两者**共用同一鉴权与授权层**（M10），差异仅在凭据形态（签名 vs 会话）。

**注**：B1 原文「用户只能说 webui」按此理解执行——人类**界面**限定 WebUI（不提供人类用的 CLI 交互式编辑器）；CLI/skill 面向 agent，非面向人类日常操作。CLI 的 admin 子命令（用户管理）为部署/运维例外。

### 9.2 CLI 工具族（B3/B11）

统一入口 `agenticspec`（`cli.py` 装配）：

| 命令 | 语义 | 最低角色 |
|---|---|---|
| `agenticspec auth bootstrap` | 用 `ADMIN_SSH_PUBKEY_FILE` 创建首个 admin（幂等） | 本地 DB |
| `agenticspec auth whoami` | 打印当前身份/角色/公钥指纹 | 无 |
| `agenticspec user add/list/disable/role` | 用户管理 | **admin** |
| `agenticspec user key add/revoke` | SSH 公钥登记/吊销 | **admin** |
| `agenticspec grant add/list/rm` | 文档集级授权 | **admin** |
| `agenticspec import <path>` | 导入（解析 → 提议 → 事务写入） | editor |
| `agenticspec import review <slug>` | 交互式审核提议（M03 CLI 审核器） | editor |
| `agenticspec doc list/get/delete` | 文档读取 / 软删 | reader / editor |
| `agenticspec node get/put/delete` | 节点读写（乐观锁） | reader / editor |
| `agenticspec comment list/add/resolve` | 批注读写（**调取人类标注**，B11） | reader / reviewer |
| `agenticspec doc diff <doc_id> [--from --to]` | 文档版本 diff（events 重放） | reader |
| `agenticspec render <doc_id> [--section]` | 渲染（整档 / 章节） | reader |
| `agenticspec stats` | 导入统计 / 覆盖率 | reader |

**自动签名**：CLI 从 `~/.ssh/` 或 `AGENTICSPEC_SSH_KEY` 读私钥，按 §3 M06 协议生成签名头。`auth bootstrap` 为唯一不签名的命令（它建立鉴权本身）。

### 9.3 Skill 清单（B3/B11）

coding agent 用 skill 定义，落 `skills/`：

| Skill | 用途 | 底层命令 |
|---|---|---|
| `spec-import` | 导入 markdown → 结构化库（含提议审核） | `agenticspec import` |
| `spec-read` | 按 doc_id/anchor/node_id 读取节点与文档树 | `agenticspec node/doc get` |
| `spec-write` | 结构化写入/更新/软删（含乐观锁重试） | `agenticspec node put/delete` |
| `spec-render` | 渲染整档或章节为 Markdown | `agenticspec render` |
| `spec-diff` | 查看文档版本 diff（了解他方改动） | `agenticspec doc diff` |
| **`spec-annotations`** | **调取人类用户的标注/批注**（B11 明确要求） | `agenticspec comment list` |

**skill 与 CLI 的关系**：skill 是 CLI 的**语义封装**（声明「何时用哪个命令、如何解读输出、失败如何重试、需要何种角色」），不重复实现逻辑。

**典型 agent 工作流**（skill 编排）：
```
spec-import（首次导入）
  → spec-annotations（读取人类标注，定位待修正点）
  → spec-write（按标注修订节点）
  → spec-render + spec-diff（自检产物与变更）
```

**鉴权传递**：skill 调用 CLI 时自动附带签名；agent 无需感知密码学细节，只需保证运行环境有可用 SSH 私钥且公钥已在 `users` 表登记。

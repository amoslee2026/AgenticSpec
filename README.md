# AgenticSpec

芯片设计知识库的结构化文档系统：**结构化库为唯一权威源**，人类可读格式（Markdown/HTML）均为渲染产物；Agent 可通过 CLI/API 读写节点、追溯事件、评审批注。

## 状态

**已上线**（systemd user 服务，本机 127.0.0.1:8787）。设计 → 实现 → 测试 → 部署全流程完成。

| 项 | 值 |
|---|---|
| 测试 | **813 passed**（666 单测 + 147 集成），全量一次通过 |
| 模块 | 12 个（M01–M11 + M-LR）+ 横切 M12 |
| 需求 | 54 条 REQ 全部实现 |
| 性能 | 14/17 项达标（点查 0.76ms / 章节渲染 43ms / 鉴权 P95 3.8ms） |
| 安全 | 独立复核通过（8 项断言 7 项已验，1 P2 + 6 P3 全闭环） |

## 快速开始

```bash
# 1) 数据库（幂等）
bash scripts/provision_pg.sh

# 2) 依赖
unset all_proxy ALL_PROXY && uv sync

# 3) 部署（迁移 + systemd 服务 + 自启）
bash scripts/deploy.sh

# 4) 首次使用：放置管理员公钥并重启触发自举
cp ~/.ssh/id_ed25519.pub data/admin_keys/admin.pub
systemctl --user restart agenticspec-api
uv run agenticspec auth whoami
```

WebUI：浏览器访问 http://127.0.0.1:8787/ （SSH 挑战-响应登录，无密码）
LAN 访问：`sudo bash scripts/provision_lan_tls_httpd.sh`（自签证书 + httpd 443 TLS 反代，ADR-007 S6）→ `https://<LAN_IP>/`

## 架构

```
AgenticSpec 单体（FastAPI + PG16）
├── M01 领域模型     类型 / UUIDv7 / 锚规则 / 原子 schema（LLM 无关，P6）
├── M02 存储层       13 表 + nodes HASH64 分区 + events 月分区 + 事件折叠
├── M03 导入         解析器（覆盖率 99.93%）/ 规则库 / 提议审核 / bulk 导入
├── M04 渲染         整档 + 分章节（O(子树)）/ P4 HTML 零改写
├── M05 检索         内部实现（对外能力归 LightRAG，ADR-008）
├── M06/M07 接口     28 端点（agent API + WebUI API）
├── M08 前端         React + TS + Vite（schema 驱动表单）
├── M09 校验         M09A schema 引擎 + M09B 质量门（8 detector）
├── M10 鉴权         SSH 公钥签名（SSHSIG）/ RBAC 四角色 / 会话 / 自举
├── M11 CLI          31 命令 + 6 skill（供 coding agent 调用）
├── M12 可观测性     AgenticLogger + rid 追踪 + 指标 + 健康巡检
└── M-LR 边界        LightRAG 导出包（只读，C7 暂缓联调）
```

### 核心不变量

| # | 原则 | 验证 |
|---|---|---|
| P1 | 结构化库为唯一权威源 | 无代码路径从渲染产物反向写库 |
| P2 | 一切写入 = 事件 + 实体同事务 | 事务注入测试 |
| P3 | 依赖单向（模块仅依赖已交付模块） | import 方向 lint |
| P4 | **HTML 片段零改写直通** | 往返测试 + 逐节点逐字节覆盖 |
| P5 | 口径唯一（normalize/rule_id/anchor） | 单测固定 |
| **P6** | **运行期 LLM 无关**（不调用任何 LLM） | import 白名单 + 断网 e2e + 依赖树 |

## MCP Server（M13）

AgenticSpec 提供标准 MCP（Model Context Protocol）stdio 服务，供 GigaPie/opencode 等 headless
agent 以工具方式读写知识库：

```bash
# 本地仓库
uv run agenticspec mcp serve
# 或已安装包（LAN 其他 Linux 机）：agenticspec mcp serve
```

- **身份**：每个工具调用自动用本进程 SSH 私钥签名（`AGENTICSPEC_SSH_KEY` → `~/.ssh/id_ed25519`
  → `~/.ssh/id_rsa`），身份 = 该私钥在服务端登记的公钥所绑定账号；权限 = 账号角色 + grant
  （ADR-007 §5）。bot 需独立身份时：给 bot 专属密钥并注册账号，启动时 `AGENTICSPEC_SSH_KEY` 指向它。
- **基址**：`AGENTICSPEC_API_URL`（缺省 `http://127.0.0.1:8787`）。
- **工具集**（10 个）：`docs_list` / `docs_get` / `docs_sections` / `docs_render` /
  `nodes_list` / `nodes_get` / `nodes_write` / `nodes_delete` / `refs_write` / `refs_remove`。

harness 挂载示例（stdio）：

```
command: uv
args: ["run", "--project", "/home/lxx/wrk/AgenticSpec", "agenticspec", "mcp", "serve"]
env:  AGENTICSPEC_SSH_KEY=/path/to/agent_key   （bot 独立身份时必填）
     AGENTICSPEC_API_URL=http://127.0.0.1:8787
```

## 测试

```bash
unset all_proxy ALL_PROXY

uv run pytest tests/unit -q                    # 666 passed
uv run pytest tests/integration -q             # 147 passed（需 PG）
uv run pytest tests/perf -m perf -q            # 性能基准（慢）
```

## 文档

| 路径 | 内容 |
|---|---|
| `spec/idea/` | 立项设计（design_doc / approach_analysis / trade_off_matrix / clarifications） |
| `spec/arch_spec/` | 架构规范（主契约 / 54 条 REQ / **10 份 ADR** / 数据流 / 追溯矩阵） |
| `spec/arch_spec/.review/` | 对抗评审记录（A1–A25 + B1–B11 批注 + S1–S16 安全复核） |
| `spec/standards/` | 测试语料（PCIe / CXL / JEDEC / AMBA 共 7 份） |

关键 ADR：
- [ADR-007](spec/arch_spec/ADR/ADR-007-SSH公钥签名鉴权与会话.md) SSH 公钥签名鉴权与会话
- [ADR-008](spec/arch_spec/ADR/ADR-008-M05降级与检索边界.md) M05 降级与检索边界
- [ADR-009](spec/arch_spec/ADR/ADR-009-规模化存储策略.md) 规模化存储（分区 / 外键降级 / 10k 文档）
- [ADR-010](spec/arch_spec/ADR/ADR-010-可观测性与性能监控.md) 可观测性与性能监控

## 已知限制

见 `spec/arch_spec/architecture_specification.md` §6.1（L-1..L-4）与 §6.2（B-3）：
- `figure`/`cross_ref` 无 `fragment` 字段（渲染期合成，硬换行空格丢失）
- `docs` 无原子软删端点（CLI 逐节点级联）
- **`schemas` 表与 `ATOM_SCHEMAS` 未合并**（新类型表单可渲染但写入被拒）
- 鉴权余量依赖宿主负载

## 授权

[PolyForm Noncommercial License 1.0.0](LICENSE) — 与 [AgenticLogger](https://github.com/amoslee2026/AgenticLogger) 同协议。仅限非商业用途。

# sen-incident-response-flow

把安全事件的工单编号、严重等级、受影响资产、处置阶段与责任人记录成可查询的服务，支持按等级与阶段查询工单并追溯每次流转的历史。

## 运行要求

- Go 1.26 或以上
- SQLite（本服务自带存储，不需要外部数据库）

## 构建、测试与启动

```bash
go build ./...
go test ./...
go run .
```

服务默认监听 `127.0.0.1:8080`。可用环境变量覆盖：

| 变量 | 默认值 | 用途 |
|---|---|---|
| `ADDR` | `127.0.0.1:8080` | HTTP 监听地址 |
| `DB_PATH` | `sen-incident-response-flow.db` | SQLite 数据库文件路径 |

## 已公开的入口

### `GET /healthz`

返回服务与存储状态。正常时 HTTP 200：

```json
{"status":"ok","database":"ok"}
```

存储不可用时 HTTP 503：

```json
{"error":{"code":"storage_unavailable","message":"database is not available"}}
```

### `POST /incidents`

登记新工单。请求体必须是单个 JSON 对象，只允许以下字段：

| 字段 | 要求 |
|---|---|
| `id` | 非空且非全空白字符串 |
| `severity` | `low`、`medium`、`high`、`critical` 之一 |
| `assets` | 非空字符串数组，每项非空且非全空白 |
| `owner` | 非空且非全空白字符串 |

字符串与资产顺序原样保留。新工单初始 `stage` 为 `受理`，`timeline` 仅含一条初始记录，其 `at` 为服务生成的 UTC RFC3339 时间。成功返回 HTTP 201 与工单对象：

```json
{
  "id": "INC-1",
  "severity": "high",
  "assets": ["db-01", "db-02"],
  "stage": "受理",
  "owner": "alice",
  "timeline": [{"stage": "受理", "owner": "alice", "at": "2026-10-05T08:00:00Z"}]
}
```

以相同 `id` 重复登记时，若 `severity`、`assets`（含顺序）、`owner` 与已存记录逐值相同，返回 HTTP 201 与原记录，不修改时间线；任一值不同返回 HTTP 409：

```json
{"error":{"code":"incident_conflict","message":"an incident with this id is already registered with different details"}}
```

请求体非法（不是单个 JSON 对象、含未知字段、必填字段缺失或为 null、类型不符、值非法）统一返回 HTTP 400 与 `invalid_request`；已有编号也先完成校验。失败不写入任何数据。

### `GET /incidents`

查询工单。无参数时返回 HTTP 200 与全部工单数组，按 `id` 的 UTF-8 字节序升序排列。支持筛选参数：

- `severity`：按等级筛选
- `stage`：按阶段筛选（`受理`、`遏制`、`清除`、`恢复`、`关闭` 之一），可与 `severity` 组合取交集
- `id`：按编号精确查询，只能单独使用；命中返回 HTTP 200 与单个工单对象，未命中返回 HTTP 404 与 `incident_not_found`

无匹配时返回空数组 `[]`。参数为空、值非法、重复、未知或 `id` 与筛选参数组合时返回 HTTP 400 与 `invalid_query`。

## 错误约定

所有错误响应都是单个顶层 `error` 对象，包含 `code` 与 `message` 两个字符串字段；`message` 不包含 SQL、堆栈或文件路径。

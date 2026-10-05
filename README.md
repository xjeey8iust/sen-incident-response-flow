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

登记工单。请求体必须是单个 JSON 对象，只允许以下字段：

| 字段 | 类型 | 约束 |
|---|---|---|
| `id` | string | 必填，非空且非全空白 |
| `severity` | string | 必填，只能是 `low`、`medium`、`high`、`critical` |
| `assets` | string[] | 必填，非空数组，每项非空且非全空白 |
| `owner` | string | 必填，非空且非全空白 |

字符串与资产顺序原样保留。成功时 HTTP 201，返回工单对象；初始 `stage` 为 `受理`，`timeline` 仅含初始记录，`at` 为服务生成的 UTC RFC3339 时间：

```json
{"id":"INC-1","severity":"high","assets":["db-1","web-2"],"stage":"受理","owner":"alice","timeline":[{"stage":"受理","owner":"alice","at":"2026-10-05T03:45:18Z"}]}
```

同一 `id` 重复登记时按值识别：`severity`、`assets`（含顺序）、`owner` 完全相同则返回 201 与原记录，不修改时间也不追加历史；任一值不同返回 409：

```json
{"error":{"code":"incident_conflict","message":"incident id is already registered with different attributes"}}
```

请求体不是单个 JSON 对象、含未知字段、必填字段缺失或为 null、类型不符或值非法时，统一返回 400 `invalid_request`；已有编号也会先完成校验。校验失败的请求不写入任何数据。

### `GET /incidents`

查询工单。无参数时返回 200 与工单数组，按 `id` 的 UTF-8 字节序升序排列；`severity` 与 `stage` 可分别筛选或组合取交集，无匹配时返回空数组 `[]`。`stage` 接受 `受理`、`遏制`、`清除`、`恢复`、`关闭`。

`id` 参数只能单独使用：命中时返回 200 与单个工单对象，未命中返回 404：

```json
{"error":{"code":"incident_not_found","message":"no incident is registered with this id"}}
```

参数为空、值非法、重复、未知，或 `id` 与筛选条件组合时，返回 400 `invalid_query`。

## 错误约定

所有错误响应都是单个顶层 `error` 对象，包含 `code` 与 `message` 两个字符串字段；`message` 不包含 SQL、堆栈或文件路径。

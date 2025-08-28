# S3 预签名 URL 导入/导出方案说明

- 概要: 使用 S3 作为文件中转与持久化介质，通过预签名 URL 让前端直传/直下，后端仅做授权与任务编排，从根本规避 API Gateway/Lambda 的二进制与大小限制问题。
- 结论: 生产常用、稳定成熟、扩展性好。对大文件、并发与跨终端兼容性最佳，推荐作为长期方案。

## 目标与收益
- 稳定性: 避免 API Gateway/Lambda 二进制编码/压缩/长度等链路问题，下载文件不再损坏。
- 性能: 前端直传/直下，绕开后端带宽与内存瓶颈，提升吞吐与并发。
- 扩展性: 支持大文件（GB 级）、异步处理与跨端兼容。
- 成本: 传输与存储成本清晰可控，复用 S3 生命周期与分层存储策略。
- 安全: 精确授权（限时、限类型、限大小、限路径），可选 KMS 加密与内容扫描。

## 架构与数据流

### 导出（下载）
- 同步小文件
  - 后端生成 Excel → PutObject 到 S3（设置 Content-Type/Disposition）→ 后端返回 GET 预签名 URL（短时效）→ 前端直接下载。
- 异步大文件
  - 后端创建导出任务（jobId）→ 异步 Lambda 生成 Excel 并上传 S3 → 更新任务状态与对象 Key → 客户端轮询或 Webhook → 拿到 GET 预签名 URL 下载。

### 导入（上传）
- 直接导入（小文件）
  - 后端颁发 PUT 预签名 URL（限制 content-type/大小/路径）→ 前端直传 S3 → 前端携带 Key 调用后端“导入开始”接口 → 后端读取 S3 对象并处理 → 返回导入结果。
- 事件触发（自动化）
  - 后端颁发 PUT 预签名 URL → 前端直传 S3 → S3 触发事件（ObjectCreated）→ 处理 Lambda 自动执行导入 → 产生日志/结果数据 → 后端接口用于查询导入结果。

## API 设计（功能说明，无代码）
- `POST /api/v1/customers/export`
  - 入参: 查询条件（分页/筛选/排序等）
  - 出参（小文件）: `downloadUrl`、`expireAt`、`fileName`、`size`（可选）
  - 出参（大文件异步）: `jobId`、`statusUrl`、`estimatedReadyAt`
- `GET /api/v1/customers/export/:jobId/status`
  - 出参: `status`（pending/processing/succeeded/failed）、`downloadUrl`（成功时）、错误信息
- `GET /api/v1/files/upload-url`
  - 入参: `contentType`、`fileName`、`maxSize`、`purpose`（如 import/customers）
  - 出参: `uploadUrl`、`expireAt`、`objectKey`、`headers`（如需）
- `POST /api/v1/customers/import`
  - 入参: `objectKey`、`originalFileName`、可选业务参数
  - 出参: `importResult`（成功/失败计数、错误明细），或返回 `jobId` 走异步
- `GET /api/v1/customers/import/:jobId/status`
  - 出参: 异步导入的 `status` 与结果

## 基础设施（CDK）变更（高层）
- S3 存储桶
  - CORS: 允许 `GET/PUT/HEAD`；限制来源域名；允许必要请求头（Content-Type 等）。
  - 加密: SSE-S3 或 SSE-KMS（推荐 KMS，细粒度访问控制）。
  - 生命周期: 导出临时文件自动过期删除（例如 7 天）；导入源文件可短期保存。
  - 访问日志: 开启 S3 访问日志（或 CloudTrail data events）。
- IAM 权限
  - API Lambda: `s3:PutObject`（导出）、`s3:GetObject`（导出/导入读取）、`s3:HeadObject`、可选 `s3:DeleteObject`。
  - 事件处理 Lambda（如启用自动导入）: `s3:GetObject`、DynamoDB 等业务资源权限。
- 可选触发器
  - S3 → Lambda（ObjectCreated:*）用于自动导入。
- 可选 CloudFront
  - 自定义域/性能/跨地域下载；可选签名 URL/头，隐藏 S3 源站。

## 应用端改动点（后端/前端）
- 后端
  - 颁发预签名 URL 的接口（GET 下载、PUT 上传），附加限制：Content-Type、最大体积、Key 前缀（按用户/租户/用途分隔）、有效期。
  - 导出逻辑：生成 Excel → 上传 S3 → 返回下载 URL（或返回任务）。
  - 导入逻辑：接收 S3 Key → 读取并解析 → 返回结果（或异步处理）。
  - 异步任务（可选）：任务表（DynamoDB）记录状态/失败重试/审计。
- 前端
  - 上传：先获取预签名 PUT URL → 直接 PUT 到 S3 → 用返回的 Key 调后端“导入开始”。
  - 下载：拿到 GET 预签名 URL 后直接下载，处理过期/错误等异常。
  - UI：异步任务状态轮询/通知（若启用异步）。

## 安全与合规
- 预签名限制
  - 有效期（常用 1–10 分钟）。
  - 路径隔离（`prefix/userId/purpose/uuid`），避免越权覆盖。
  - Content-Type/Content-Length 条件限制（防走样）。
- 访问控制
  - 仅认证用户可请求预签名；对象 Key 命名含 userId/租户前缀；导入处理校验归属。
- 加密与审计
  - SSE-KMS 加密（CMK）；CloudTrail data events 记录访问；S3 访问日志。
- 内容安全（可选）
  - 病毒扫描；白名单 Content-Type 校验。
- 隐私
  - 可用 CloudFront 隐藏 S3 域名；或依赖短有效期预签名。

## 性能与成本
- 性能
  - 前端直传/直下，绕开 API Gateway/Lambda 带宽与冷启动瓶颈。
  - 异步生成/导入，避免接口超时（默认 30s 可调）。
- 成本
  - S3 存储/请求与数据传出费用；Lambda 计算费用；CloudFront（如启用）。
- 优化
  - 导出大文件异步生成 + 生命周期清理；必要时压缩 CSV/ZIP（权衡 CPU/带宽）。

## 稳定性评估
- 成熟度高：行业通用，云原生最佳实践。
- 风险点集中在权限与生命周期配置：规范预签名与 Key 管理可显著降低风险。
- 故障域清晰：S3 高可用；Lambda 异步可重试；失败可通过状态表与告警恢复。
- 兼容性强：不受 API Gateway 二进制/大小限制影响，兼容多浏览器与移动端。

## 监控与可观测性
- 指标：导出/导入请求量、成功率、时延；任务队列（待处理、超时、失败率）；S3 对象数与存储量（按前缀）。
- 日志：Lambda（生成/导入）日志；S3 访问日志/CloudTrail data events；API 调用审计。
- 告警：失败率/超时、队列堆积（异步任务）、异常下载量尖峰。

## 迁移与兼容策略
- 渐进迁移
  - 保留现有导出接口路径，内部改为“返回 302 重定向到预签名下载 URL”或直接返回 JSON+URL，前端逐步适配。
  - 导入先支持两条路径（旧直传 API & 新 S3 直传），逐步引导流量切换。
- 回滚
  - 保持旧逻辑分支（开关），遇问题可快速切回；预签名 URL 为短时效，过期后自动失效。

## 风险与应对
- 预签名 URL 泄漏：短有效期 + 最小权限 + KMS 加密 + 审计。
- 大文件导出超时：异步任务 + 分片/分页生成 + 增加内存与超时。
- 导入非法文件：Content-Type/大小限制 + 服务器侧严格校验 + 病毒扫描。
- 存储膨胀：生命周期策略 + 清理任务。
- 客户端兼容：提供文件名/Content-Disposition 元数据，适配 iOS/Safari。

## 验收标准
- 导出
  - 小文件（<10MB）1 次请求内返回 URL 并可成功下载且可打开。
  - 大文件异步生成，状态查询清晰，失败错误可见；下载统计/审计可用。
- 导入
  - 多 10MB 文件可直传且后端能稳定处理；非法文件拒绝并有清晰报错；处理结果（成功/失败行数、错误明细）可追溯。
- 安全
  - 未授权用户无法获取预签名；预签名过期后不可用；对象不可被跨用户读取/覆盖。
- 监控
  - 关键指标/日志/告警可用、可视化。

## 实施清单（无代码，实现任务项）
- S3
  - 创建/复用文件桶；设置 CORS（GET/PUT/HEAD、限制来源域名与必要头）；启用 SSE-KMS；配置生命周期（导出临时 7 天、导入原始 7–30 天）。
- IAM
  - 授权 API Lambda 对指定前缀的 `Put/Get/Head/DeleteObject`；若启用 S3 事件，授权处理 Lambda。
- API（后端）
  - 设计并实现四个接口（颁发上传 URL、启动导入、启动导出、任务状态查询）。
  - 制定同步/异步策略（阈值与切换条件）。
  - 任务表与状态机（可选）。
- 前端
  - 调整上传逻辑为直传 S3；下载逻辑使用获取到的 URL；异步任务的 UI 状态与错误处理。
- 监控/告警
  - CloudWatch 指标、日志、报警规则；S3 访问日志/CloudTrail data events（选配）。
- 文档与运维
  - 编写操作手册（过期时间、失败排查流程、数据清理）；安全评审（KMS、权限、域名/CORS）。

## 里程碑建议（规划参考）
- M1（1–2 天）: 方案评审与细化、CDK/CORS/KMS/Lifecycle 设计、接口契约冻结。
- M2（2–4 天）: 颁发上传/下载 URL 接口、同步导出、直传导入打通（小文件）。
- M3（3–5 天）: 异步导出/导入、任务表与状态查询、告警/监控接入。
- M4（1–2 天）: 渐进切换与回滚开关、文档与运维手册、性能与安全复盘。


# 流式 LLM Lambda 需求说明

## 背景
为了解耦 AI 模型调用与核心业务逻辑，将基于 Mastra 框架的 LLM 应用独立为 AWS Lambda。

## 目标
- 提供一个专门的目录，用于编写并构建 Mastra LLM 应用。
- 构建结果生成独立 `dist`，部署到单独的 AWS Lambda。
- NestJS 服务通过 AWS SDK 调用该 Lambda，获取流式返回。
- 基础逻辑仍留在 NestJS，前端在需要时可直接调用此 Lambda。

## 目录规划
```
llm-lambda/
  src/         # Mastra 应用源码
  dist/        # 构建产物
  README.md    # 需求说明（本文档）
```

## 交互流程
1. **开发**：在 `src/` 中使用 Mastra 编写流式 LLM 逻辑。
2. **构建**：通过构建脚本产出 `dist/`，并打包上传至 AWS Lambda。
3. **调用**：
   - NestJS 内部：使用 AWS SDK 请求 Lambda，处理流式返回。
   - 前端：可直接通过 API Gateway 调用 Lambda，绕过 NestJS。

## 管理优势
- AI 逻辑与主服务完全隔离，便于版本迭代与权限控制。
- Lambda 无状态、按需扩缩，适合模型推理的弹性负载。
- NestJS 仅承担业务编排与鉴权，结构清晰。

# Yarn Workspaces 改造指南

## 概述

本指南基于方案一（Yarn Workspaces），旨在将 `llm-lambda` 与主应用代码解耦，使两者各自维护依赖并独立打包部署。

## 改造前

- 单一 `package.json` 管理所有依赖。
- `llm-lambda` 与主业务代码共享 `node_modules`，构建时会将 LLM 依赖一并打包。

## 改造后

- 仓库根目录启用 Yarn Workspaces。
- 主应用与 `llm-lambda` 各自拥有独立 `package.json` 与构建脚本。
- 构建/部署时可仅安装和打包目标子包的生产依赖，避免多余体积。

## 改造流程

1. **调整目录结构**
   - 将现有代码拆分为 `backend/`（主业务）与 `llm-lambda/` 两个子目录。
2. **配置根 `package.json`**
   - 添加 `"private": true`，并声明 `workspaces`：
     ```json
     {
       "private": true,
       "workspaces": ["backend", "llm-lambda"]
     }
     ```
3. **初始化子包**
   - 在 `backend/package.json` 中保留主业务依赖与脚本。
   - 在 `llm-lambda/package.json` 中仅声明 LLM 所需依赖和构建脚本。
4. **依赖安装与构建**
   - 使用 `yarn install` 安装全部依赖。
   - 构建主应用：`yarn workspace backend build`。
   - 构建 LLM Lambda：`yarn workspace llm-lambda build`。
5. **部署与打包**
   - CDK 中将各 Lambda 指向对应子包目录。
   - 生产环境可使用 `yarn workspaces focus --production <pkg>` 裁剪依赖。

## 改造进度记录

| 步骤                 | 进度 | 备注 |
| -------------------- | ---- | ---- |
| 目录拆分             | ☐    |      |
| 根 package.json 配置 | ☐    |      |
| 子包初始化           | ☐    |      |
| 构建验证             | ☐    |      |
| 部署验证             | ☐    |      |

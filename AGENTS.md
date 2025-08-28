# Repository Guidelines

## 项目结构与模块组织
- `src/`: NestJS 应用入口；常见文件：`*.module.ts`、`*.service.ts`、`*.controller.ts`。
- `src/modules/`: 业务模块（`user`、`customer`、`product`、`transaction`、`file`、`stats`）。
- `src/auth`、`src/common`、`src/shared`、`src/config`、`src/database`: 鉴权、通用组件与配置。
- `infrastructure/`: AWS CDK 基础设施工程（部署、对比、销毁）。
- `scripts/`: 开发/构建/部署脚本；产物目录：`dist/`，Lambda 包：`lambda-package/`。
- `test/`: 测试（Node 原生命令为主，含 Jest e2e 示例）。

## 构建、测试与本地开发
- 启动开发：`npm run start:dev`（热更新）。生产启动：`npm run start:prod`。
- 构建：`npm run build`；Lambda 打包：`npm run build:lambda`。
- 单元测试：`npm test`（Node 的 `node:test`，示例见 `test/node.test.js`）。
- 代码质量：`npm run lint`、`npm run format`（pre-commit 会自动格式化）。
- 基础设施（CDK）：`npm run cdk:diff:dev|prod`、`npm run cdk:deploy:dev|prod`、`npm run cdk:destroy:*`。

## 代码风格与命名规范
- 缩进 2 空格；`singleQuote: true`、`semi: true`、`trailingComma: all`（参见 `.prettierrc`）。
- 文件名 kebab-case（如 `user.controller.ts`）；类/接口 PascalCase；变量/函数 camelCase。
- 导入优先使用别名 `@/...`（配置见 `tsconfig.json`）。提交前请确保 `lint/format` 通过。

## 测试指南
- 单元测试：位于 `test/*.test.js`，运行 `npm test`。
- 端到端（可选）：`test/jest-e2e.json` 已配置 `supertest`；如需运行：`npx jest -c test/jest-e2e.json`。
- 基础设施测试：`cd infrastructure && npm test`（Jest）。

## 提交与 Pull Request 规范
- 提交遵循 Conventional Commits：`feat(auth): ...`、`fix(stats): ...`、`style: ...`。一次提交只做一件事。
- 分支命名：`feature/<slug>`、`fix/<slug>`。
- PR 内容：变更摘要、动机与影响、验证步骤（命令/curl）、必要截图（如 Swagger），关联 Issue；确保 `lint/format` 通过。

## 安全与配置提示
- 禁止提交密钥与 `.env`；以 `.env.example` 为模板在本地配置，或使用 AWS CLI 配置凭证。
- 通过 `--context environment=dev|prod` 选择 CDK 环境；推荐使用现有 npm 脚本统一操作。

## 面向自动化代理（Agent）的协作说明
- 范围最小化：仅修改与任务直接相关的文件，避免无关重构与大规模格式化。
- 风格一致：遵循 ESLint/Prettier 与命名规范；优先使用路径别名 `@/`。
- 运行与验证：`npm run start:dev`、`npm test`、`npm run build`/`build:lambda`、`npm run cdk:diff:dev`/`deploy:dev`。
- 文档同步：接口变更需完善 Swagger 注释；新增模块遵循 `*.module.ts`/`*.service.ts`/`*.controller.ts` 结构。

## 面向 AI 编程工具的输出提示
- 默认中文：面向用户的说明、步骤与结果总结优先使用中文（必要英文术语括注原文）。思考过程也使用中文
- 操作预告：执行命令或改动前，用 1–2 句中文说明目的与下一步计划。
- 变更摘要：完成后用中文列出变更文件/核心改动/潜在影响/回滚方式。
- 命令与日志：保留英文原始输出，但附中文解读与下一步建议。
- 提交与 PR：前缀遵循 Conventional Commits（英文），可追加简短中文说明；PR 建议包含「变更摘要/动机背景/影响范围/验证步骤/回滚方案/关联 Issue」。

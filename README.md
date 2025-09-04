<div align="center">
  <h1>⚡️ AWS CDK + NestJS Template ⚡️</h1>
  <p><em>Bootstrap a serverless backend in minutes.</em></p>
</div>

[中文文档 / Chinese Guide](docs/项目模板使用指南.zh-CN.md)

## Purpose

This template accelerates building serverless applications with NestJS and the AWS Cloud Development Kit (CDK). It bundles a ready-to-use architecture featuring API Gateway + Lambda, DynamoDB, S3, and Cognito so you can focus on business logic instead of boilerplate infrastructure.

## Features

- **NestJS** framework with TypeScript
- **AWS CDK** infrastructure as code
- **Serverless Stack**: API Gateway, Lambda, DynamoDB, S3, Cognito
- **Environment-aware** configuration for dev and prod
- **Testing & Linting** via Node's test runner (`node:test`), ESLint, and Prettier
- **Scripts** for development, building, and deploying

### Feature Highlights

- Import/Export module (S3-based): Generate presigned URLs for uploads, export data to S3 and return short-lived download links (CSV/Excel flows supported by service layer).
- Standard CRUD scaffolding: Example feature modules (`customers`, `products`) with validated DTOs, pagination, and Swagger docs.
- Keep-warm via CDK: EventBridge periodically calls the health endpoint to reduce Lambda cold starts in deployed environments.
- Basic auth flows: User registration, email verification, login, profile, and password change backed by Amazon Cognito + JWT for API protection.
- DynamoDB integration: Pay-per-request tables with practical GSIs; table names and regions are wired via environment variables and CDK outputs.

## Online Demo

- URL: https://main.d3919bjo2q9c5.amplifyapp.com/
- Test account: `linuo`
- Test password: `Ur8Djfm6vtuf9Lc!`

## Project Structure

```
├── backend/            # NestJS application (NestJS 11 + TypeScript)
│   └── src/
│       ├── modules/    # Feature modules (user, customer, product, ...)
│       ├── auth/       # AuthN/AuthZ (Cognito + JWT)
│       ├── common/     # Common utilities, interceptors, pipes, filters
│       ├── shared/     # Cross-cutting helpers
│       ├── config/     # App configuration (environment-aware)
│       └── database/   # DynamoDB integration
├── llm-lambda/         # Additional Lambda workspace (LLM example/integration)
├── infrastructure/     # AWS CDK stacks (deploy/diff/destroy)
├── scripts/            # Dev/build/deploy helper scripts
├── docs/               # Documentation
├── dist/               # Build outputs (generated)
├── lambda-package/     # Lambda bundles (generated)
└── package.json        # Root workspace config and scripts
```

## Getting Started

### Prerequisites

- Node.js 20+
- npm or Yarn
- AWS CLI & credentials
- AWS CDK v2 (`npm i -g aws-cdk`)

### Installation

```bash
# install dependencies
yarn      # or: npm install

# copy base env files (will be completed after deploy)
cp .env.example .env
yes | cp .env backend/.env
```

Important: On first run you must provision infrastructure and copy the EnvFileContent block from deployment logs into your env files before starting the app.

```bash
# provision dev infrastructure (prints Stack Outputs)
npm run deploy:dev   # or: yarn deploy:dev

# then copy the `EnvFileContent` output block from the deployment logs
# paste it into `.env` and `backend/.env` (overwrite same-name vars)
# tip: `ApiEndpoint` output shows the API Gateway URL for quick testing
```

### Development

```bash
npm run backend:start:dev
# API: http://localhost:3000/api/v1
# Swagger: http://localhost:3000/api/v1/docs
```

Alternatively, run directly in the workspace:

```bash
cd backend
npm run start:dev
```

### Common Scripts

- Build: `npm run backend:build`
- Lambda bundle: `npm run backend:build:lambda` or `npm run build:lambda`
- Quality: `npm run lint`, `npm run format`
- Tests: `npm test` (Node's `node:test` in each workspace)

### Deployment (CDK)

```bash
# dev environment
npm run deploy:dev

# production environment
npm run deploy:prod
```

Diff and destroy helpers:

```bash
npm run cdk:diff:dev
npm run cdk:diff:prod

npm run destroy:lambda:dev
npm run destroy:lambda:prod
```

Notes:

- Scripts pass `--context environment=dev|prod` to CDK and default stack name to `linuo-aws-template-<env>`.
- Override stack name via `--context stackName=<name>`.

### Post-Deploy Verification

- Use the `ApiEndpoint` printed in deploy logs to access the API Gateway URL.
- Health: `GET {apiBase}/health`
- Swagger (non-prod): `{apiBase}/docs`

### Lambda Packaging

- Entry: `backend/src/lambda.ts`
- Webpack config: `backend/webpack.lambda.config.js`
- Bundle script: `scripts/build-lambda.sh`
- Output directory: `lambda-package/`
- Tip: most deps are bundled; `swagger-ui-dist` is external and copied as static assets. Swagger is disabled in prod by env.

More details and troubleshooting tips are available in the [Chinese guide](docs/项目模板使用指南.zh-CN.md). If variables look different, compare with `docs/CDK_OUTPUT_EXAMPLE.md`, but always prefer the `EnvFileContent` from current deploy logs.

### Frontend Template

- Repository: [aws-nextjs-amplify-template](https://github.com/lfhwnqe/aws-nextjs-amplify-template)
- Compatibility: The frontend template matches this backend template's API responses. After you deploy the backend and paste the `EnvFileContent` into `.env` and `backend/.env`, you can start end-to-end development immediately.
- API Base: Combine the deploy log's `ApiEndpoint` with your `API_PREFIX` (from `.env`), for example: `https://<api-id>.execute-api.<region>.amazonaws.com/dev/api/v1`.
- CORS: Backend CORS is open by default for convenience; restrict it to trusted origins in production.

## Import/Export (S3) Quickstart

- Get a presigned URL to upload an import file:
  - POST `{apiBase}/import-export/imports/presigned-url` with `{ fileName, contentType, type: "customer|product|transaction" }`.
  - Upload the file to the returned `uploadUrl` using HTTP PUT.
- Export data as Excel and fetch a short-lived download URL:
  - GET `{apiBase}/customers/export` or `{apiBase}/products/export` (JWT required). Response includes `downloadUrl` and `expireAt`.
- Import from S3 key (server-side):
  - POST `{apiBase}/customers/imports/s3` or `{apiBase}/products/imports/s3` with `{ key }`.

Environment variables come from the CDK deploy logs: copy the `EnvFileContent` block into `.env` and `backend/.env` (includes `S3_IMPORT_EXPORT_BUCKET_NAME`, Cognito, DynamoDB, regions, etc.).

### Troubleshooting

- AWS credentials missing: run `aws configure` or export `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` locally.
- First-time CDK bootstrap: `cd infrastructure && cdk bootstrap`.
- Port in use: adjust `PORT` in `backend/.env` or free port 3000.
- Swagger not available in prod: by design; disabled in production.
- Auth 401/403: check Cognito and JWT-related env vars; try public health endpoint first.

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/awesome`)
3. Commit with [Conventional Commits](https://www.conventionalcommits.org/)
4. Open a pull request

## Repo Activity

<p align="center">
  <a href="https://repobeats.axiom.co" target="_blank" rel="noopener noreferrer">
    <img
      src="https://repobeats.axiom.co/api/embed/cf7ac95ff5e42f909c41824acf1902c37ffe9dc0.svg"
      alt="Repobeats analytics for this repository"
      title="Repobeats analytics"
      width="100%"
    />
  </a>
  <br />
  <sub>Traffic and activity overview, auto-updated by Repobeats.</sub>
  <br />
</p>
## License

MIT

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
- **Testing & Linting** setup with Jest and ESLint
- **Scripts** for development, building, and deploying

## Project Structure

```
├── backend/          # NestJS application
├── infrastructure/   # AWS CDK stacks
├── scripts/          # Helper scripts
├── docs/             # Documentation
└── package.json      # Root workspace config
```

## Getting Started

### Prerequisites

- Node.js 18+
- npm or Yarn
- AWS CLI & credentials
- AWS CDK v2 (`npm i -g aws-cdk`)

### Installation

```bash
# install dependencies
yarn      # or: npm install

# copy environment variables
cp .env.example .env
yes | cp .env backend/.env
```

### Development

```bash
npm run backend:start:dev
# API: http://localhost:3000/api/v1
# Swagger: http://localhost:3000/api/v1/docs
```

### Deployment

```bash
# dev environment
npm run deploy:dev

# production environment
npm run deploy:prod
```

More details and troubleshooting tips are available in the [Chinese guide](docs/项目模板使用指南.zh-CN.md).

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/awesome`)
3. Commit with [Conventional Commits](https://www.conventionalcommits.org/)
4. Open a pull request

## License

MIT

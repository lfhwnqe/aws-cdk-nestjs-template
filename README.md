# Trade Management Backend

A modern NestJS backend application for trade management with AWS CDK deployment infrastructure.

## 🚀 Features

- **NestJS Framework**: Built with the latest NestJS framework for scalable server-side applications
- **AWS Integration**: Full integration with AWS services (S3, Cognito, DynamoDB)
- **Infrastructure as Code**: AWS CDK for infrastructure deployment and management
- **Multi-Environment Support**: Separate configurations for development and production
- **Authentication & Authorization**: JWT-based auth with AWS Cognito integration
- **File Management**: S3-based file storage with presigned URLs
- **API Documentation**: Auto-generated Swagger/OpenAPI documentation
- **Type Safety**: Full TypeScript support with strict type checking
- **Testing**: Comprehensive unit and e2e testing setup
- **Code Quality**: ESLint, Prettier, and pre-commit hooks

## 🏗️ Architecture

```
├── src/
│   ├── auth/                 # Authentication module
│   ├── common/               # Shared decorators, filters, interceptors
│   ├── config/               # Configuration management
│   ├── database/             # DynamoDB service and configuration
│   ├── modules/              # Business logic modules
│   │   ├── user/             # User management
│   │   ├── customer/         # Customer management
│   │   ├── product/          # Product management
│   │   ├── transaction/      # Transaction management
│   │   ├── file/             # File management
│   │   └── stats/            # Statistics and analytics
│   └── shared/               # Shared services (S3, Cognito)
├── infrastructure/         # AWS CDK infrastructure code
├── scripts/               # Deployment and development scripts
└── test/                 # Test files
```

## 🛠️ Prerequisites

- Node.js 18+
- npm or yarn
- AWS CLI configured
- AWS CDK CLI (`npm install -g aws-cdk`)

## 📦 Quick Start

### 1. Setup

```bash
# Clone and setup the project
git clone <repository-url>
cd trade-manage-backend

# Run setup script
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### 2. Configuration

```bash
# Copy environment template (root)
cp .env.example .env

# Backend service loads env from backend/.env or backend/.env.local
# If you keep the template at repo root, sync it to backend/.env for local dev
mkdir -p backend
cp .env backend/.env

# Update env values as needed (do not commit secrets)
# Optional: also maintain backend/.env.development and backend/.env.production
```

### 3. AWS Setup

```bash
# Configure AWS CLI (if not already done)
aws configure

# Bootstrap CDK (first time only)
cd infrastructure
cdk bootstrap
cd ..
```

### 4. Development

```bash
# Start development server
npm run start:dev
# or
./scripts/dev.sh start

# API will be available at: http://localhost:3000/api/v1
# Swagger docs at: http://localhost:3000/api/v1/docs
```

## 🚀 Deployment

### Development Environment

```bash
# Deploy to development
npm run deploy:dev
# or
./scripts/deploy.sh -e dev
```

### Production Environment

```bash
# Deploy to production
npm run deploy:prod
# or
./scripts/deploy.sh -e prod
```

### Lambda 打包与维护指南

当前 deploy 速度优化点：lambda 代码包通过 webpack 打包绝大部分依赖，不再在 `lambda-package` 目录执行 `npm install`。仅将 `swagger-ui-dist` 标记为 external 并拷贝其静态资源，其余依赖会被打包进 `lambda.js`。

- 入口与配置：
  - 入口文件：`src/lambda.ts`
  - 打包配置：`webpack.lambda.config.js`
  - 打包脚本：`scripts/build-lambda.sh`
  - 产物目录：`lambda-package/`（包含 `lambda.js` 与 `node_modules/swagger-ui-dist`）

- 重要策略：
  - 依赖打包：默认将业务需要的依赖打入 bundle，减少部署时的安装与上传体积。
  - External 例外：仅 `swagger-ui-dist` 作为 external，并在脚本中复制静态资产以供 Swagger UI 使用。
  - 忽略可选模块：通过 webpack `IgnorePlugin` 与 `alias` 将未使用的 Nest 可选模块（`@nestjs/microservices`、`@nestjs/websockets` 等）标记忽略，避免不必要的解析与报错。

- Swagger 开关（强制 dev-only）：
  - 通过环境变量 `SWAGGER_ENABLED` 控制是否启用 Swagger 文档。
  - CDK 已为 Lambda 注入：`prod` 环境为 `false`，其他环境为 `true`。
  - 运行时在 `src/lambda.ts` 内进行判断，并在需要时动态加载 `@nestjs/swagger`，生产环境不会暴露文档路由。

- 什么时候需要改 webpack 配置？
  - 新增依赖“需要在运行时以文件形式存在”的情况：
    - 例如依赖包含大量静态资源或需要在运行时读取的文件，考虑将其 external，并在 `build-lambda.sh` 中增加复制步骤（类似 `swagger-ui-dist`）。
  - 引入 Nest 可选子模块（microservices/websockets）：
    - 若开始使用，请移除 `webpack.lambda.config.js` 中对应的 IgnorePlugin/alias 配置，并确保安装相关依赖。
  - 使用原生二进制依赖（如 `bcrypt`、`sharp` 等）：
    - 这类包涉及平台特定二进制，建议改用纯 JS 版本（当前项目使用 `bcryptjs`），或采用 Lambda Layer/自定义构建（需额外适配）。
  - 你希望将某些大依赖从 bundle 中排除：
    - 可将其加入 externals，并在 `build-lambda.sh` 中明确复制相应目录到 `lambda-package/node_modules`。否则会在运行时报模块缺失。

- 新增依赖的建议流程：
  1) 安装依赖并在代码中正常 `import`。
  2) 运行 `npm run build:lambda`，检查是否能成功打包。
  3) 如出现“模块未找到/运行时报资源缺失”，判断是否需要：
     - 将依赖 external 并在脚本中复制资源目录；或
     - 去掉 external，让 webpack 将依赖打进 bundle；或
     - 调整 IgnorePlugin/alias，允许打包 Nest 可选模块。

- 进一步优化（可选）：
  - 若在 Lambda 环境禁用 Swagger，可移除 `swagger-ui-dist` 的 external 与复制步骤，包体可继续减小。
  - 可切换到 esbuild 以进一步加速打包（需引入构建依赖并调整配置）。


### Destroy Stack

#### Development Environment
```bash
# Destroy development stack
npm run destroy:dev
# or
./scripts/deploy.sh -e dev --destroy
```

#### Production Environment
```bash
# Destroy production stack
npm run destroy:prod
# or
./scripts/deploy.sh -e prod --destroy
```

## 📚 API Documentation

Once the server is running, visit:
- **Swagger UI**: `http://localhost:3000/api/v1/docs`
- **API Base URL**: `http://localhost:3000/api/v1`

### Main Endpoints

- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `GET /auth/profile` - Get user profile
- `GET /users/me` - Get current user info
- `POST /transactions` - Create new transaction
- `GET /transactions` - List transactions
- `POST /files/upload` - Upload file
- `GET /files` - List files

## 🧪 Testing

```bash
# Run unit tests
npm run test

# Run tests in watch mode
npm run test:watch

# Run e2e tests
npm run test:e2e

# Generate coverage report
npm run test:cov
```

## 🔧 Development Scripts

```bash
# Development server with hot reload
npm run start:dev

# Build for production (outputs to build/ directory)
npm run build

# Start production server from build output
npm run start:prod

# Lint code
npm run lint

# Format code
npm run format

# Development helper script
./scripts/dev.sh [start|test|lint|format|clean|reset|docs]
```

## 🏗️ AWS Services

### DynamoDB Tables
- **Users Table**: User profiles and authentication data
- **Transactions Table**: Trading records and history
- **Files Table**: File metadata and references

### S3 Buckets
- **File Storage**: Secure file storage with presigned URLs
- **Versioning**: Enabled for data protection
- **Lifecycle Rules**: Automatic cleanup of incomplete uploads

### Cognito
- **User Pool**: User authentication and management
- **JWT Tokens**: Secure API access
- **Password Policies**: Configurable security requirements

## 🔒 Security Features

- JWT-based authentication
- Role-based access control (RBAC)
- Input validation with class-validator
- Helmet.js for security headers
- CORS configuration
- Environment-based secrets management

## 📁 Environment Variables

### Required Variables
```bash
# Application
NODE_ENV=development|production
PORT=3000
APP_NAME=trade-manage-backend

# AWS Configuration
AWS_REGION=ap-southeast-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key

# S3
S3_BUCKET_NAME=your-bucket-name
S3_REGION=ap-southeast-1

# Cognito
COGNITO_USER_POOL_ID=your-user-pool-id
COGNITO_CLIENT_ID=your-client-id
COGNITO_REGION=ap-southeast-1

# DynamoDB
DYNAMODB_REGION=ap-southeast-1
DYNAMODB_TABLE_PREFIX=trade-manage-dev

# JWT
JWT_SECRET=your-jwt-secret
JWT_EXPIRES_IN=24h
```

## 🐛 Troubleshooting

### Common Issues

1. **AWS Credentials Not Found**
   ```bash
   aws configure
   # or set environment variables
   export AWS_ACCESS_KEY_ID=your-key
   export AWS_SECRET_ACCESS_KEY=your-secret
   ```

2. **CDK Bootstrap Required**
   ```bash
   cd infrastructure
   cdk bootstrap
   ```

3. **Port Already in Use**
   ```bash
   # Change PORT in .env file or kill existing process
   lsof -ti:3000 | xargs kill -9
   ```

4. **DynamoDB Connection Issues**
   - Verify AWS credentials
   - Check region configuration
   - Ensure tables are created via CDK deployment

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review AWS documentation for service-specific issues

## 🔄 Version History

- **v1.0.0** - Initial release with core functionality
  - NestJS framework setup
  - AWS services integration
  - CDK infrastructure
  - Authentication system
  - File management
  - Trade management

---

**Built with ❤️ using NestJS and AWS**

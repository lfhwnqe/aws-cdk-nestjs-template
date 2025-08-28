# 环境配置说明

## 概述

本项目使用AWS服务，支持多种环境下的凭证管理方式：

- **Lambda环境**：自动使用IAM角色（无需配置凭证）
- **本地开发**：使用环境变量或AWS CLI配置
- **CI/CD**：使用环境变量

## 部署后的环境配置

### 1. CDK部署后获取配置

部署CDK后，会输出完整的`.env`文件内容：

```bash
cdk deploy TradeManageStack-dev
```

输出示例：
```
TradeManageStack-dev.EnvFileContent = 
=== COPY THE CONTENT BELOW TO YOUR .env FILE ===

# Application Configuration
NODE_ENV=development
PORT=3000
APP_NAME=trade-manage-backend

# AWS Configuration
AWS_REGION=ap-southeast-1

# AWS S3 Configuration
S3_BUCKET_NAME=trade-manage-files-dev-ap-southeast-1
S3_REGION=ap-southeast-1

# AWS Cognito Configuration
COGNITO_USER_POOL_ID=ap-southeast-1_Jo4YfDt5w
COGNITO_CLIENT_ID=16fronbt3jpgp6cj7k2479tbrh
COGNITO_REGION=ap-southeast-1

...

=== END OF .env FILE CONTENT ===
```

### 2. 复制配置到.env文件

直接复制`=== COPY THE CONTENT BELOW TO YOUR .env FILE ===`和`=== END OF .env FILE CONTENT ===`之间的内容到项目根目录的`.env`文件。

## AWS凭证配置

### 本地开发环境

有两种方式设置AWS凭证：

#### 方式1：环境变量（推荐）
```bash
export AWS_ACCESS_KEY_ID=your-access-key-id
export AWS_SECRET_ACCESS_KEY=your-secret-access-key
export AWS_REGION=ap-southeast-1
```

#### 方式2：AWS CLI配置
```bash
aws configure
```

### Lambda环境

Lambda函数会自动使用分配的IAM角色，无需额外配置。

## 安全注意事项

⚠️ **重要**：
- 绝对不要在代码中硬编码AWS凭证
- 不要将包含真实凭证的`.env`文件提交到版本控制
- 使用`.env.example`作为模板，不包含真实凭证
- 生产环境使用IAM角色而不是访问密钥

## 启动应用

```bash
npm run start:dev
```

如果遇到AWS凭证错误，请检查：
1. 环境变量是否正确设置
2. AWS CLI是否配置
3. IAM权限是否足够

# CDK部署输出示例

## 部署命令

```bash
yarn deploy:dev
```

## 输出示例

部署完成后，你会看到类似以下的输出：

```
✅  TradeManageStack-dev

✨  Deployment time: 45.67s

Outputs:
TradeManageStack-dev.ApiEndpoint = https://a760bohec4.execute-api.ap-southeast-1.amazonaws.com/dev/
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

# AWS DynamoDB Configuration
DYNAMODB_REGION=ap-southeast-1
DYNAMODB_TABLE_PREFIX=trade-manage-dev

# JWT Configuration
JWT_SECRET=dev-secret-key
JWT_EXPIRES_IN=24h

# Database Configuration
DB_TABLE_USERS=trade-manage-dev-users
DB_TABLE_TRADES=trade-manage-dev-trades
DB_TABLE_FILES=trade-manage-dev-files
DB_TABLE_CUSTOMERS=trade-manage-dev-customers
DB_TABLE_PRODUCTS=trade-manage-dev-products
DB_TABLE_CUSTOMER_PRODUCT_TRANSACTIONS=trade-manage-dev-customer-product-transactions

# API Configuration
API_PREFIX=api/v1
SWAGGER_TITLE=Trade Management API
SWAGGER_DESCRIPTION=API for Trade Management System
SWAGGER_VERSION=1.0.0

# Deployment Information (for reference)
API_GATEWAY_URL=https://a760bohec4.execute-api.ap-southeast-1.amazonaws.com/dev/
API_GATEWAY_ID=a760bohec4
API_LAMBDA_FUNCTION_NAME=trade-manage-api-dev

=== END OF .env FILE CONTENT ===

NOTES:
- AWS credentials are handled automatically by AWS SDK
- In Lambda: Uses IAM roles (no credentials needed)
- Local development: Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY as environment variables
- Never commit AWS credentials to code!

Stack ARN: arn:aws:cloudformation:ap-southeast-1:123456789012:stack/TradeManageStack-dev/12345678-1234-1234-1234-123456789012
```

## 使用方法

1. **复制配置**：直接复制`=== COPY THE CONTENT BELOW TO YOUR .env FILE ===`和`=== END OF .env FILE CONTENT ===`之间的所有内容

2. **粘贴到.env文件**：将复制的内容粘贴到项目根目录的`.env`文件中

3. **设置AWS凭证**（仅本地开发需要）：

   ```bash
   export AWS_ACCESS_KEY_ID=your-access-key-id
   export AWS_SECRET_ACCESS_KEY=your-secret-access-key
   ```

4. **启动应用**：
   ```bash
   npm run start:dev
   ```

## 注意事项

- ✅ CDK输出的内容可以直接使用，无需额外处理
- ✅ AWS凭证通过环境变量或AWS CLI配置管理
- ✅ Lambda环境自动使用IAM角色
- ❌ 绝不在代码中硬编码AWS凭证

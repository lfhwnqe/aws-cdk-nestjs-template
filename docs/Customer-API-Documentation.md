# 客户信息管理 API 文档

## 概述

客户信息管理模块提供了完整的客户信息CRUD操作，包括创建、查询、更新和删除客户信息。所有API都需要JWT认证，部分操作需要管理员权限。

## 基础信息

- **基础路径**: `/api/v1/customers`
- **认证方式**: JWT Bearer Token
- **内容类型**: `application/json`

## 数据模型

### 客户实体 (Customer)

```typescript
{
  customerId: string;        // 客户ID，格式：cust_xxxxxxxx
  email: string;             // 邮箱地址（唯一）
  phone: string;             // 手机号码（唯一）
  firstName: string;         // 名
  lastName: string;          // 姓
  idType: '身份证' | '护照' | '其他';  // 身份证件类型
  idNumber: string;          // 身份证件号码
  dateOfBirth: string;       // 出生日期 (YYYY-MM-DD)
  address: string;           // 联系地址
  riskLevel: '低' | '中' | '高';     // 风险承受等级
  status: 'active' | 'inactive' | 'suspended';  // 客户状态
  createdAt: string;         // 创建时间 (ISO 8601)
  updatedAt: string;         // 更新时间 (ISO 8601)
}
```

## API 端点

### 1. 创建客户

**POST** `/customers`

创建新的客户信息。

**权限要求**: USER 或 ADMIN

**请求体**:
```json
{
  "email": "customer@example.com",
  "phone": "+86 138 0013 8000",
  "firstName": "小明",
  "lastName": "张",
  "idType": "身份证",
  "idNumber": "110101199001011234",
  "dateOfBirth": "1990-01-01",
  "address": "北京市朝阳区某某街道123号",
  "riskLevel": "中",
  "status": "active"  // 可选，默认为 active
}
```

**响应**:
- **201 Created**: 客户创建成功
- **400 Bad Request**: 请求参数错误
- **409 Conflict**: 邮箱或手机号已存在
- **401 Unauthorized**: 未授权

### 2. 获取客户列表

**GET** `/customers`

获取客户列表，支持分页、筛选和搜索。

**权限要求**: USER 或 ADMIN

**查询参数**:
- `page` (number, 可选): 页码，默认为 1
- `limit` (number, 可选): 每页数量，默认为 10，最大 100
- `search` (string, 可选): 搜索关键词（支持姓名、邮箱、手机号）
- `status` (string, 可选): 客户状态筛选
- `riskLevel` (string, 可选): 风险等级筛选
- `startDate` (string, 可选): 创建时间开始日期 (YYYY-MM-DD)
- `endDate` (string, 可选): 创建时间结束日期 (YYYY-MM-DD)
- `sortBy` (string, 可选): 排序字段，默认为 createdAt
- `sortOrder` (string, 可选): 排序方向 (asc/desc)，默认为 desc

**响应**:
```json
{
  "data": [/* 客户列表 */],
  "total": 100,
  "page": 1,
  "limit": 10,
  "totalPages": 10
}
```

### 3. 获取客户详情

**GET** `/customers/{id}`

根据客户ID获取客户详细信息。

**权限要求**: USER 或 ADMIN

**路径参数**:
- `id` (string): 客户ID

**响应**:
- **200 OK**: 返回客户详情
- **404 Not Found**: 客户不存在
- **401 Unauthorized**: 未授权

### 4. 根据邮箱查找客户

**GET** `/customers/search/email/{email}`

根据邮箱地址查找客户。

**权限要求**: USER 或 ADMIN

**路径参数**:
- `email` (string): 客户邮箱

### 5. 根据手机号查找客户

**GET** `/customers/search/phone/{phone}`

根据手机号查找客户。

**权限要求**: USER 或 ADMIN

**路径参数**:
- `phone` (string): 客户手机号

### 6. 更新客户信息

**PUT** `/customers/{id}`

更新客户信息。

**权限要求**: USER 或 ADMIN

**路径参数**:
- `id` (string): 客户ID

**请求体**: 与创建客户相同，但所有字段都是可选的

**响应**:
- **200 OK**: 更新成功
- **404 Not Found**: 客户不存在
- **400 Bad Request**: 请求参数错误
- **409 Conflict**: 邮箱或手机号已存在

### 7. 删除客户

**DELETE** `/customers/{id}`

删除客户信息。

**权限要求**: ADMIN

**路径参数**:
- `id` (string): 客户ID

**响应**:
- **200 OK**: 删除成功
- **404 Not Found**: 客户不存在
- **401 Unauthorized**: 未授权
- **403 Forbidden**: 权限不足

## 数据验证规则

### 邮箱验证
- 必须是有效的邮箱格式
- 在系统中必须唯一

### 手机号验证
- 支持中国大陆手机号格式：`+86 138 0013 8000` 或 `13800138000`
- 在系统中必须唯一

### 姓名验证
- 长度：1-50个字符
- 不能为空

### 身份证件号码
- 长度：6-30个字符
- 不能为空

### 地址验证
- 长度：5-200个字符
- 不能为空

### 出生日期
- 必须是有效的日期格式 (YYYY-MM-DD)

## 错误处理

所有API都遵循统一的错误响应格式：

```json
{
  "statusCode": 400,
  "message": "错误描述",
  "error": "Bad Request"
}
```

常见错误码：
- **400**: 请求参数错误
- **401**: 未授权
- **403**: 权限不足
- **404**: 资源不存在
- **409**: 资源冲突（如邮箱或手机号已存在）
- **500**: 服务器内部错误

## 使用示例

### 创建客户示例

```bash
curl -X POST "https://api.example.com/api/v1/customers" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "zhang.xiaoming@example.com",
    "phone": "+86 138 0013 8000",
    "firstName": "小明",
    "lastName": "张",
    "idType": "身份证",
    "idNumber": "110101199001011234",
    "dateOfBirth": "1990-01-01",
    "address": "北京市朝阳区某某街道123号",
    "riskLevel": "中"
  }'
```

### 查询客户列表示例

```bash
curl -X GET "https://api.example.com/api/v1/customers?page=1&limit=10&status=active&search=张" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 注意事项

1. 所有时间字段都使用ISO 8601格式
2. 客户ID自动生成，格式为 `cust_` + UUID
3. 邮箱和手机号在系统中必须唯一
4. 删除操作需要管理员权限
5. 支持通过邮箱和手机号快速查找客户
6. 查询列表支持多种筛选和排序选项

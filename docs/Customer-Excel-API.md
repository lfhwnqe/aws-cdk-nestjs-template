# 客户Excel导入导出API文档

本文档描述了客户管理模块中新增的Excel导入导出功能。

## 概述

新增了两个API接口：
- `GET /customers/export` - 导出所有客户数据为Excel文件
- `POST /customers/import` - 从Excel文件批量导入客户数据

## API接口详情

### 1. 导出客户数据

**接口**: `GET /customers/export`

**描述**: 将所有客户数据导出为Excel文件

**权限要求**: USER 或 ADMIN

**请求头**:
```
Authorization: Bearer <JWT_TOKEN>
```

**响应**:
- **成功响应** (200):
  - Content-Type: `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`
  - Content-Disposition: `attachment; filename="customers_YYYY-MM-DD.xlsx"`
  - 返回Excel文件的二进制数据

**Excel文件包含的列**:
- 客户ID
- 邮箱
- 手机号
- 姓
- 名
- 身份证件类型
- 身份证件号码
- 出生日期
- 联系地址
- 风险承受等级
- 客户状态
- 创建时间
- 更新时间

**示例请求**:
```bash
curl -X GET "http://localhost:3000/customers/export" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -o customers.xlsx
```

### 2. 导入客户数据

**接口**: `POST /customers/import`

**描述**: 从Excel文件批量导入客户数据

**权限要求**: USER 或 ADMIN

**请求头**:
```
Authorization: Bearer <JWT_TOKEN>
Content-Type: multipart/form-data
```

**请求体**:
- `file`: Excel文件 (.xlsx 或 .xls 格式)

**Excel文件格式要求**:

必须包含以下列（第一行为标题行）：
- 邮箱 (必填)
- 手机号 (必填)
- 姓 (必填)
- 名 (必填)
- 身份证件类型 (必填，值：身份证/护照/其他)
- 身份证件号码 (必填)
- 出生日期 (必填，格式：YYYY-MM-DD)
- 联系地址 (必填)
- 风险承受等级 (必填，值：低/中/高)
- 客户状态 (可选，值：active/inactive/suspended，默认：active)

**响应**:
```json
{
  "successCount": 10,
  "failureCount": 2,
  "skippedCount": 1,
  "totalCount": 13,
  "errors": [
    {
      "row": 3,
      "error": "邮箱格式不正确",
      "data": {
        "email": "invalid-email",
        "phone": "+86 138 0013 8000",
        "firstName": "小明",
        "lastName": "张"
      }
    }
  ],
  "message": "导入完成：成功 10 条，失败 2 条，跳过 1 条"
}
```

**示例请求**:
```bash
curl -X POST "http://localhost:3000/customers/import" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -F "file=@customers.xlsx"
```

## 错误处理

### 导出接口错误
- **400 Bad Request**: 导出失败
- **401 Unauthorized**: 未授权

### 导入接口错误
- **400 Bad Request**: 文件格式错误或数据验证失败
- **401 Unauthorized**: 未授权
- **415 Unsupported Media Type**: 不支持的文件格式

## 数据验证规则

### 邮箱验证
- 必须符合标准邮箱格式
- 不能与现有客户重复

### 手机号验证
- 必须符合中国大陆手机号格式：`+86 1[3-9]xxxxxxxxx` 或 `1[3-9]xxxxxxxxx`
- 不能与现有客户重复

### 身份证件类型
- 必须是以下值之一：`身份证`、`护照`、`其他`

### 风险承受等级
- 必须是以下值之一：`低`、`中`、`高`

### 客户状态
- 必须是以下值之一：`active`、`inactive`、`suspended`
- 如果不提供，默认为 `active`

### 出生日期
- 必须是 `YYYY-MM-DD` 格式
- 必须是有效日期

## 导入行为说明

1. **重复数据处理**: 如果邮箱或手机号已存在，该条记录会被跳过
2. **错误处理**: 数据验证失败的记录会被记录在错误列表中，不会影响其他有效记录的导入
3. **事务性**: 每条记录独立处理，单条记录失败不会影响其他记录
4. **日志记录**: 所有导入操作都会记录详细日志

## 性能考虑

- 导出功能会获取所有客户数据，对于大量数据可能需要较长时间
- 导入功能逐条验证和插入数据，建议单次导入不超过1000条记录
- 建议在低峰期进行大批量数据导入导出操作

## 安全考虑

- 所有接口都需要JWT认证
- 支持ADMIN和USER角色访问
- 文件上传限制为Excel格式
- 导入数据会进行完整的业务逻辑验证

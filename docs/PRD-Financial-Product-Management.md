# 金融产品管理系统 - 产品需求文档 (PRD)

## 1. 项目概述

### 1.1 项目背景
交易管理后端系统需要扩展功能，支持金融产品的管理和客户购买记录的追踪。当前系统主要处理股票交易，现需要增加对各类金融产品（如理财产品、基金、债券等）的管理能力，以及客户与产品之间的关联关系管理。

### 1.2 项目目标
- 建立完整的金融产品信息管理体系
- 实现客户信息的统一管理
- 追踪和管理客户的产品购买记录
- 为管理员提供全面的数据管理和分析功能
- 支持未来业务扩展需求

### 1.3 项目范围
本次需求专注于数据库设计和基础设施搭建，包括：
- DynamoDB表结构设计与实现
- CDK基础设施代码更新
- 数据模型定义
- 不包括业务逻辑API的实现

## 2. 业务需求分析

### 2.1 核心业务场景

#### 2.1.1 客户信息管理
- **需求描述**: 系统需要存储和管理客户的基本信息
- **关键功能**:
  - 客户基本信息录入（姓名、联系方式、身份信息）
  - 客户信息查询和更新
  - 支持通过邮箱和手机号快速查找客户
  - 客户信息的完整性验证

#### 2.1.2 产品信息管理
- **需求描述**: 管理各类金融产品的基础信息
- **关键功能**:
  - 产品基础信息管理（名称、描述、类型）
  - 产品收益信息管理（固定收益率、结息日期）
  - 产品状态管理（上架、下架、暂停销售）
  - 产品分类和筛选功能

#### 2.1.3 客户产品关联记录
- **需求描述**: 记录客户购买产品的完整交易信息
- **关键功能**:
  - 购买记录创建和管理
  - 交易状态跟踪（待确认、已确认、已完成、已取消）
  - 购买金额和数量记录
  - 交易时间戳记录

### 2.2 管理员功能需求

#### 2.2.1 数据管理功能
- 产品信息的CRUD操作
- 客户信息的CRUD操作
- 客户购买记录的管理和查询

#### 2.2.2 数据分析功能
- 客户购买情况统计分析
- 产品销售情况分析
- 交易趋势分析
- 客户行为分析

## 3. 数据库设计

### 3.1 设计原则
- **MVP原则**: 字段设计精简实用，避免过度复杂化
- **可扩展性**: 预留未来功能扩展空间
- **查询效率**: 基于常见查询模式设计索引
- **成本优化**: 采用按需付费模式，优化存储成本

### 3.2 表结构设计

#### 3.2.1 客户信息表 (customers)

**表名**: `trade-manage-{environment}-customers`

**主键设计**:
- Partition Key: `customerId` (String) - 客户唯一标识符

**全局二级索引**:
1. **EmailIndex**
   - Partition Key: `email` (String)
   - 用途: 支持通过邮箱快速查找客户

2. **PhoneIndex**
   - Partition Key: `phone` (String)
   - 用途: 支持通过手机号快速查找客户

**字段定义**:
```json
{
  "customerId": "string",      // 客户ID (主键)
  "email": "string",           // 邮箱地址 (必填，唯一)
  "phone": "string",           // 手机号码 (必填)
  "firstName": "string",       // 名
  "lastName": "string",        // 姓
  "idType": "string",          // 身份证件类型 (身份证/护照/其他)
  "idNumber": "string",        // 身份证件号码
  "dateOfBirth": "string",     // 出生日期 (ISO 8601格式)
  "address": "string",         // 联系地址
  "riskLevel": "string",       // 风险承受等级 (低/中/高)
  "status": "string",          // 客户状态 (active/inactive/suspended)
  "createdAt": "string",       // 创建时间 (ISO 8601格式)
  "updatedAt": "string"        // 更新时间 (ISO 8601格式)
}
```

#### 3.2.2 产品信息表 (products)

**表名**: `trade-manage-{environment}-products`

**主键设计**:
- Partition Key: `productId` (String) - 产品唯一标识符

**全局二级索引**:
1. **ProductTypeIndex**
   - Partition Key: `productType` (String)
   - Sort Key: `createdAt` (String)
   - 用途: 按产品类型查询，支持时间排序

2. **StatusIndex**
   - Partition Key: `status` (String)
   - Sort Key: `createdAt` (String)
   - 用途: 按产品状态查询，支持时间排序

**字段定义**:
```json
{
  "productId": "string",           // 产品ID (主键)
  "productName": "string",         // 产品名称 (必填)
  "productType": "string",         // 产品类型 (理财/基金/债券/保险)
  "description": "string",         // 产品描述
  "riskLevel": "string",           // 风险等级 (低/中/高)
  "minInvestment": "number",       // 最低投资金额
  "maxInvestment": "number",       // 最高投资金额
  "expectedReturn": "number",      // 预期年化收益率 (百分比)
  "interestPaymentDate": "string", // 结息日期 (每月/每季度/每年)
  "maturityPeriod": "number",      // 产品期限 (天数)
  "status": "string",              // 产品状态 (active/inactive/suspended)
  "salesStartDate": "string",      // 销售开始日期
  "salesEndDate": "string",        // 销售结束日期
  "createdAt": "string",           // 创建时间
  "updatedAt": "string"            // 更新时间
}
```

#### 3.2.3 客户产品购买记录表 (customer_product_transactions)

**表名**: `trade-manage-{environment}-customer-product-transactions`

**主键设计**:
- Partition Key: `transactionId` (String) - 交易唯一标识符
- Sort Key: `createdAt` (String) - 创建时间

**全局二级索引**:
1. **CustomerTransactionsIndex**
   - Partition Key: `customerId` (String)
   - Sort Key: `createdAt` (String)
   - 用途: 查询特定客户的所有交易记录

2. **ProductTransactionsIndex**
   - Partition Key: `productId` (String)
   - Sort Key: `createdAt` (String)
   - 用途: 查询特定产品的所有交易记录

3. **TransactionStatusIndex**
   - Partition Key: `transactionStatus` (String)
   - Sort Key: `createdAt` (String)
   - 用途: 按交易状态查询，支持时间排序

**字段定义**:
```json
{
  "transactionId": "string",       // 交易ID (主键)
  "customerId": "string",          // 客户ID (外键)
  "productId": "string",           // 产品ID (外键)
  "transactionType": "string",     // 交易类型 (purchase/redeem)
  "quantity": "number",            // 购买数量/份额
  "unitPrice": "number",           // 单价
  "totalAmount": "number",         // 总金额
  "transactionStatus": "string",   // 交易状态 (pending/confirmed/completed/cancelled)
  "paymentMethod": "string",       // 支付方式 (bank_transfer/card/other)
  "expectedMaturityDate": "string", // 预期到期日期
  "actualReturnRate": "number",    // 实际收益率 (完成后填写)
  "notes": "string",               // 备注信息
  "createdAt": "string",           // 创建时间 (排序键)
  "updatedAt": "string",           // 更新时间
  "completedAt": "string"          // 完成时间 (可选)
}
```

### 3.3 查询模式分析

#### 3.3.1 常见查询场景
1. **客户相关查询**:
   - 通过客户ID查询客户信息
   - 通过邮箱查询客户信息
   - 通过手机号查询客户信息
   - 查询客户的所有购买记录

2. **产品相关查询**:
   - 通过产品ID查询产品信息
   - 按产品类型筛选产品
   - 按产品状态筛选产品
   - 查询产品的所有销售记录

3. **交易相关查询**:
   - 查询特定时间范围的交易记录
   - 按交易状态筛选交易
   - 统计客户购买金额
   - 统计产品销售情况

#### 3.3.2 索引使用策略
- 主键查询: 直接使用表的主键进行高效查询
- GSI查询: 利用全局二级索引支持多维度查询
- 复合查询: 结合多个索引实现复杂查询需求

## 4. 技术实现

### 4.1 CDK基础设施更新
- 在现有CDK Stack中添加三个新的DynamoDB表
- 配置适当的索引和权限
- 更新Lambda函数的环境变量和权限

### 4.2 AWS最佳实践
- 使用按需付费计费模式
- 启用加密和备份（生产环境）
- 合理设置删除策略
- 优化索引设计以控制成本

## 5. 部署和配置

### 5.1 环境变量配置
新增以下环境变量：
```
DB_TABLE_CUSTOMERS=trade-manage-{environment}-customers
DB_TABLE_PRODUCTS=trade-manage-{environment}-products
DB_TABLE_CUSTOMER_PRODUCT_TRANSACTIONS=trade-manage-{environment}-customer-product-transactions
```

### 5.2 权限配置
Lambda函数需要对新表的读写权限：
- customers表: 读写权限
- products表: 读写权限
- customer_product_transactions表: 读写权限

## 6. 后续开发建议

### 6.1 API开发
基于此数据库设计，建议开发以下API模块：
- 客户管理API (Customer Management)
- 产品管理API (Product Management)
- 交易记录API (Transaction Management)

### 6.2 数据验证
- 实现客户信息的完整性验证
- 产品信息的业务规则验证
- 交易数据的一致性检查

### 6.3 性能优化
- 监控查询性能
- 根据实际使用情况调整索引
- 考虑数据归档策略

## 7. 风险和限制

### 7.1 技术风险
- DynamoDB查询限制需要合理设计查询模式
- 索引数量会影响写入成本
- 数据一致性需要应用层保证

### 7.2 业务风险
- 数据模型变更可能影响现有功能
- 需要考虑数据迁移策略
- 权限控制需要严格管理

## 8. 总结

本PRD文档定义了金融产品管理系统的数据库设计方案，采用MVP原则确保实现的精简性和实用性。通过合理的表结构设计和索引配置，能够支持当前的业务需求，同时为未来的功能扩展预留空间。

建议按照本文档的设计方案实施数据库部署，并在后续开发中严格遵循设计原则，确保系统的稳定性和可扩展性。

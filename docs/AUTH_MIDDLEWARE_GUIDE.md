# 认证中间件和白名单管理指南

## 概述

本项目现在使用认证中间件 (`AuthMiddleware`) 来处理 JWT 认证，并在 `AppModule` 中配置白名单路由管理。这种方式比使用全局守卫更灵活，可以精确控制哪些路由需要认证。

## 架构变更

### 之前的方式
- 使用全局 `JwtAuthGuard`
- 通过 `@Public()` 装饰器标记公开路由
- 需要在每个控制器上添加 `@UseGuards(JwtAuthGuard)`

### 现在的方式
- 使用 `AuthMiddleware` 中间件
- 在 `AppModule` 中配置白名单路由
- 自动处理所有路由的认证，除了白名单中的路由

## 文件结构

```
src/
├── auth/
│   ├── middleware/
│   │   └── auth.middleware.ts          # 认证中间件
│   ├── guards/
│   │   ├── jwt-auth.guard.ts          # 保留但不再全局使用
│   │   └── roles.guard.ts             # 角色守卫 (新增)
│   └── auth.module.ts                 # 导出中间件和守卫
├── app.module.ts                      # 配置中间件和白名单
└── ...
```

## 核心组件

### 1. AuthMiddleware

位置: `src/auth/middleware/auth.middleware.ts`

功能:
- 从请求头提取 JWT 令牌
- 验证令牌有效性
- 将用户信息附加到请求对象

```typescript
// 自动为所有非白名单路由提供认证
// 用户信息可通过 @CurrentUser() 装饰器获取
```

### 2. 白名单配置

位置: `src/app.module.ts`

当前白名单路由:
```typescript
.exclude(
  // 认证相关路由
  'api/v1/auth/login',
  'api/v1/auth/register',
  // 应用基础路由
  'api/v1/',
  'api/v1/health',
  // API 文档路由
  'api/v1/docs',
  'api/v1/docs/(.*)',
  // 根路径和健康检查
  '/',
  '/health',
)
```

### 3. 角色守卫

位置: `src/auth/guards/roles.guard.ts`

用于需要特定角色权限的路由:
```typescript
@Get()
@Roles(Role.ADMIN)
@UseGuards(RolesGuard)
findAll() {
  // 只有管理员可以访问
}
```

## 如何添加新的白名单路由

1. 编辑 `src/app.module.ts`
2. 在 `exclude()` 方法中添加新路由
3. 注意包含正确的 API 前缀 (`api/v1/`)

示例:
```typescript
.exclude(
  // 现有路由...
  'api/v1/auth/login',
  'api/v1/auth/register',
  
  // 新增的公开路由
  'api/v1/svg-parser/parse',
  'api/v1/svg-parser/parse-string',
  'api/v1/mindmap',
)
```

## 如何使用角色权限

对于需要特定角色的路由，使用 `@Roles()` 装饰器和 `RolesGuard`:

```typescript
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles, Role } from '../../common/decorators/roles.decorator';

@Controller('admin')
export class AdminController {
  
  @Get('users')
  @Roles(Role.ADMIN)
  @UseGuards(RolesGuard)
  getAllUsers() {
    // 只有管理员可以访问
  }
  
  @Get('stats')
  @Roles(Role.ADMIN, Role.MODERATOR)
  @UseGuards(RolesGuard)
  getStats() {
    // 管理员和版主都可以访问
  }
}
```

## 测试认证中间件

### 方法1: 使用测试脚本
```bash
# 确保应用正在运行
npm run start:dev

# 在另一个终端运行测试
node test-auth-middleware.js
```

### 方法2: 手动测试
```bash
# 测试白名单路由 (应该返回 200)
curl http://localhost:3000/api/v1/auth/login

# 测试需要认证的路由 (应该返回 401)
curl http://localhost:3000/api/v1/users

# 测试带认证的路由 (需要先登录获取 token)
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:3000/api/v1/users
```

## 常见问题

### Q: 如何添加不需要认证的新路由？
A: 在 `app.module.ts` 的 `exclude()` 中添加路由路径。

### Q: 如何为特定路由添加角色权限？
A: 使用 `@Roles()` 装饰器和 `@UseGuards(RolesGuard)`。

### Q: 中间件和守卫的区别？
A: 中间件在路由处理之前运行，守卫在路由处理时运行。中间件用于认证，守卫用于授权。

### Q: 如何获取当前用户信息？
A: 使用 `@CurrentUser()` 装饰器:
```typescript
@Get('profile')
getProfile(@CurrentUser() user: any) {
  // user 包含 userId, username, email, role
}

@Get('my-data')
getMyData(@CurrentUser('userId') userId: string) {
  // 直接获取 userId
}
```

## 迁移指南

如果你有现有的控制器使用 `@UseGuards(JwtAuthGuard)`:

1. 移除 `@UseGuards(JwtAuthGuard)` (认证现在自动处理)
2. 保留 `@ApiBearerAuth('JWT-auth')` (用于 Swagger 文档)
3. 如果需要角色权限，添加 `@UseGuards(RolesGuard)` 和 `@Roles()`

## 安全注意事项

1. 确保所有敏感路由都不在白名单中
2. 定期审查白名单配置
3. 使用强密钥配置 JWT
4. 考虑添加速率限制中间件
5. 在生产环境中禁用 API 文档路由

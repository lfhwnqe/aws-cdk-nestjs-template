# 认证中间件和白名单管理指南

## 概述

本项目现在使用认证中间件 (`AuthMiddleware`) 来处理 JWT 认证，并在 `AppModule` 中配置白名单路由管理。这种方式比使用全局守卫更灵活，可以精确控制哪些路由需要认证。

## 分步实施与可验证清单

以下步骤将本指南的要求拆解为可操作、可验证的最小单元。每一步都包含“实施”和“验证”两部分，完成后即可确认达标。

1) 准备与基础配置
- 实施: 确认全局注册 `JwtModule` 且加载 `jwt.secret`、`jwt.expiresIn`；确保配置来源于 `configuration.ts` 与 `.env`/`.env.local`（例如 `JWT_SECRET`、`JWT_EXPIRES_IN`）。
- 验证: 运行 `npm run build` 成功；若本地启动，`npm run start:dev` 无报错，控制台输出包含全局前缀（默认 `api/v1`）。

2) 实施 AuthMiddleware
- 实施: 在 `backend/src/auth/middleware/auth.middleware.ts` 中从 `Authorization: Bearer <token>` 解析 JWT，使用 `JwtService.verifyAsync` 按 `jwt.secret` 校验；校验成功将 `{ userId, username, email, role }` 挂载到 `req.user`，失败抛出 `UnauthorizedException`。
- 验证: 启动服务后，访问一个需要认证的受保护路由（如 `GET /api/v1/products`），无 Token 返回 401；携带有效 Token 返回 200 且服务端可读取 `req.user`。

3) 在 AppModule 应用中间件并配置白名单
- 实施: 在 `backend/src/app.module.ts` 中使用 `consumer.apply(AuthMiddleware).exclude(...).forRoutes('*')`；白名单至少包含登录/注册/健康检查/根路径/文档路由。注意：代码里的 `exclude` 路径不包含全局前缀（例如写 `auth/login`），对外请求路径依然是 `api/v1/auth/login`。
- 验证: 使用 curl 手动验证：
  - `GET /api/v1/health`、`GET /api/v1/`、`GET /api/v1/docs` 在未携带 Token 时应 200。
  - `GET /api/v1/products` 在未携带 Token 时应 401；携带有效 Token 时应 200。

4) 迁移控制器（从全局守卫到中间件）
- 实施: 移除控制器/路由上的 `@UseGuards(JwtAuthGuard)`（认证统一由中间件处理）；保留 `@ApiBearerAuth('JWT-auth')` 以支持 Swagger 试调。
- 验证: 代码检索不应再出现 `JwtAuthGuard` 的全局使用/绑定；`npm run build` 通过；通过 Swagger 在受保护路由中带上 Authorize 后可正常访问。

5) 配置与使用角色守卫（授权）
- 实施: 在 `backend/src/auth/guards/roles.guard.ts` 中基于 `@Roles(...roles)` 元数据与 `req.user.role` 进行校验；在需要的控制器路由上添加 `@UseGuards(RolesGuard)` 和 `@Roles(Role.ADMIN, ...)`。
- 验证: 为同一路由分别使用不含目标角色与含目标角色的 Token 请求：前者应 403，后者 200。

6) 使用 `@CurrentUser()` 装饰器读取用户
- 实施: 在控制器方法参数中使用 `@CurrentUser()` 或 `@CurrentUser('userId')` 读取注入的用户信息。
- 验证: 在任一受保护接口中临时输出或断点检查可获取 `userId/role` 等字段；无 Token 时中间件应先拦截为 401。

7) 白名单变更流程
- 实施: 新增公开路由时，仅在 `AppModule.exclude()` 添加相应项；对外文档/工具中标注其对外完整路径（含前缀），代码中保持不含前缀的路径写法。
- 验证: 新增后逐一通过 curl 验证未携带 Token 可 200；同时验证非白名单受保护路由仍返回 401。

8) 安全基线检查
- 实施: 定期审查白名单，避免将敏感路由纳入；确保 `JWT_SECRET` 为强随机值；在生产环境关闭/限制文档访问；按需增加速率限制/日志审计。
- 验证: 
  - 配置: `.env` 中存在强 `JWT_SECRET`，生产环境 `NODE_ENV=production` 下不暴露 `/api/v1/docs`；
  - 行为: 使用无效/过期 Token 均返回 401；权限不足返回 403；白名单外的所有路由都需要 Token。

9) 手动与脚本化联调
- 实施: 使用项目自带 curl 示例或临时 Node 脚本，对白名单/受保护/带角色限制的路由进行全链路验证。
- 验证: 参考“测试认证中间件”章节，三类请求（白名单 200、无 Token 401、携 Token 200/403）均符合预期。

10) 验收清单（完成即勾选）
- 受保护路由默认需要认证；白名单路由无需认证。
- 合法 Token 可访问受保护路由并在 `@CurrentUser()` 读到用户信息。
- 角色不足返回 403，角色满足返回 200。
- 生产环境下文档访问受控，密钥安全要求达标。

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

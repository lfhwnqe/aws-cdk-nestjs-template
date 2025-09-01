# 基于 AWS Cognito JWT 的鉴权改造方案（全量切换版）

## 文档目标
- 立即将系统从“自签 JWT”切换为“完全基于 AWS Cognito JWT”的鉴权体系。
- 统一所有后端服务的令牌验证逻辑，仅接受 Cognito 颁发的 JWT。
- 移除自签令牌相关代码、配置与文档，不保留回滚与双栈兼容路径。

## 范围与不在范围
- 范围：后端鉴权链路、登录/刷新/登出接口、配置与中间件调整、其他服务验签指引、监控与验收。
- 不在范围：前端改造（Hosted UI/PKCE 细节）、非鉴权业务逻辑与 UI 改动。

## 目标状态
- 令牌来源：登录获取 Cognito 原生 `access_token`（推荐）与 `id_token`（可选）。服务器不再签发任何自定义 JWT。
- 鉴权模式：所有后端服务统一通过 Cognito JWKS 校验 RS256 JWT；不分发对称密钥。
- 用户信息：从 JWT claims 映射至 `req.user`，授权基于 `cognito:groups` 或 `custom:role`。

## 关键决策
- Token 类型：优先验证 `access_token`；如业务需要可同时接受 `id_token`。
- 角色来源：优先使用 `cognito:groups`；必要时使用自定义属性 `custom:role` 承载。
- 登录方式二选一：
  - 方式A（后端直连）：后端调用 Cognito AuthFlow（`USER_PASSWORD_AUTH`），返回原生 tokens。
  - 方式B（Hosted UI）：前端使用 Cognito 托管登录，后端仅校验传入 token。

## 角色与用户组映射（与现有 Role 枚举对齐）
- 统一使用 Cognito 用户组表示角色，名称与代码枚举严格一致：
  - `Role.SUPER_ADMIN` ↔ 组名：`super_admin`
  - `Role.ADMIN` ↔ 组名：`admin`
  - `Role.USER` ↔ 组名：`user`
  - `Role.MODERATOR` ↔ 组名：`moderator`
  - `Role.CUSTOMER` ↔ 组名：`customer`
- 后端在 JWT 解析后将 `cognito:groups` 映射到 `req.user.groups`；若需要单一 `req.user.role`，可按优先级从 groups 推导或读取 `custom:role`。

## 配置与环境变量（强制）
- `COGNITO_USER_POOL_ID`
- `COGNITO_CLIENT_ID`
- `COGNITO_REGION`

可选：
- `COGNITO_CLIENT_SECRET`（若 App Client 启用）
- `COGNITO_TOKEN_USE=access`（默认 `access`，可设 `id`）
- `COGNITO_JWKS_CACHE_TTL=600`（JWKS 缓存秒数）

清理（立即移除）：
- 删除 `JWT_SECRET`、`JWT_EXPIRES_IN` 等自签相关配置与依赖描述。

## 接口与行为变更
- `POST /auth/login`
  - 行为：调用 Cognito `InitiateAuth(USER_PASSWORD_AUTH)`，返回 `{ access_token, id_token, refresh_token, expires_in, token_type }`。
  - 不再返回自签 `access_token`。
- `POST /auth/refresh`（新增）
  - 行为：使用 `REFRESH_TOKEN_AUTH` 刷新 tokens。
- `POST /auth/logout`（可选）
  - 行为：调用 `GlobalSignOut` 或 `RevokeToken`。
- 注册/验证/改密
  - 保持基于 Cognito 的现有实现；去除与本地密码校验的耦合代码。

## 本服务改造任务
依赖调整：
- 新增：`aws-jwt-verify`
- 移除：`@nestjs/jwt`（如已无其他用途）、`jsonwebtoken`（如存在）

代码改造：
- `shared/services/cognito.service.ts`
  - 新增 `initiateAuth(username, password)`（`InitiateAuthCommand` with USER_PASSWORD_AUTH）
  - 新增 `refreshAuth(refreshToken)`（`InitiateAuth` with REFRESH_TOKEN_AUTH）
  - 可选新增 `globalSignOut(username)`、`revokeToken(refreshToken)`
- `auth/auth.service.ts`
  - 重写 `login()`：调用 Cognito，返回原生 tokens；删除 `validateUser()`、删除自签 `JwtService.sign`。
  - 新增 `refresh()`、`logout()` 对接 Cognito。
- `auth/middleware/auth.middleware.ts`
  - 替换为基于 `CognitoJwtVerifier` 的验证：仅接受 Cognito JWT。
  - 将 payload 映射到 `req.user = { userId: sub, email, groups, role }`。
- `auth/strategies/*`
  - 物理删除 `LocalStrategy` 与自签 `JwtStrategy`（及其引用）。
- `config/configuration.ts`
  - 新增/完善 `cognito.tokenUse`、`cognito.jwksCacheTtl` 等；删除自签 JWT 相关配置导出。
- 数据层
  - 停止写入/读取 DynamoDB `password` 字段；保留字段仅用于历史审计（后续可清理）。
- Swagger
  - 更新 `auth/login`/`refresh`/`logout` 响应模型；Bearer 描述为“Cognito JWT”。

文档与脚本：
- 更新 `.env.example`：仅保留 `COGNITO_*` 必要变量，移除 `JWT_*`。
- 更新 README/开发指南：登录与鉴权说明改为 Cognito。

必要代码同步（授权判断）：
- 中间件：确保把 `cognito:groups` 写入 `req.user.groups`，并可选填充 `req.user.role`。
- `RolesGuard`：在原有按 `user.role` 判断的基础上，新增按 `user.groups` 命中即可放行的逻辑。

示例（`RolesGuard` 增强版）：
```ts
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY, Role } from '@/common/decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!required || required.length === 0) return true;

    const { user } = context.switchToHttp().getRequest();
    if (!user) return false;

    const groups: string[] = Array.isArray(user.groups) ? user.groups : [];
    const role: string | undefined = user.role;
    const norm = (v: string) => String(v).toLowerCase();

    const groupSet = new Set(groups.map(norm));
    return required.some((r) => groupSet.has(norm(String(r))) || (role && norm(role) === norm(String(r))));
  }
}
```

## 其他服务改造任务
- 依赖：新增 `aws-jwt-verify`。
- 中间件/守卫：实现统一 `CognitoVerifier`，从 `Authorization: Bearer` 提取并校验。
- 用户上下文：映射 `req.user = { userId: sub, email, groups, role }`。
- 授权：基于 `cognito:groups` 或 `custom:role` 执行权限控制。

## 在 Cognito 中创建角色组并分配用户（必做）
在对应的 User Pool 中创建下面这些组（如存在则跳过）：`super_admin`、`admin`、`user`、`moderator`、`customer`。

- 控制台方式：Cognito → User pools → 选择你的池 → Users and groups → Create group。
- CLI 方式（示例）：
```bash
aws cognito-idp create-group --user-pool-id <POOL_ID> --group-name super_admin
aws cognito-idp create-group --user-pool-id <POOL_ID> --group-name admin
aws cognito-idp create-group --user-pool-id <POOL_ID> --group-name user
aws cognito-idp create-group --user-pool-id <POOL_ID> --group-name moderator
aws cognito-idp create-group --user-pool-id <POOL_ID> --group-name customer

# 将用户加入到对应组
aws cognito-idp admin-add-user-to-group --user-pool-id <POOL_ID> --username <USERNAME> --group-name super_admin
```

注意：组变更仅对新签发的 token 生效；请在角色变更后提示用户重新登录或刷新 token。

## CDK 部署与 `cognito:groups` 生效时机
- `cognito:groups` 是 Cognito 在“签发新 token”时根据“用户当前所属组”动态写入的声明（claim）。
- 你不会在 CDK 中“写入 claim”；CDK 只能“定义资源”（创建用户组、配置池/客户端）。
- 何时出现在 token：用户登录或刷新（`refresh_token`）时由 Cognito 生成的新 token 会包含最新的组信息；已签发的旧 token 不会被修改。

实践建议：
1) 用 CDK 创建用户组（基础设施层）
2) 用部署后脚本或自定义资源把指定用户加入组（数据/初始化层）
3) 让用户重新登录或刷新，以获取包含最新 `cognito:groups` 的 token

## CDK 代码示例（创建用户组 + 可选：部署期添加成员）
```ts
// infra example (AWS CDK v2)
import { Stack, StackProps, Duration } from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as cr from 'aws-cdk-lib/custom-resources';
import { Construct } from 'constructs';

export class AuthStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // 已有 User Pool：可通过环境变量导入（推荐）
    const userPoolId = process.env.COGNITO_USER_POOL_ID!;
    const userPool = cognito.UserPool.fromUserPoolId(this, 'ImportedUserPool', userPoolId);

    // 使用 L1 资源创建组（对导入的池同样生效）
    const groups = ['super_admin', 'admin', 'user', 'moderator', 'customer'];
    groups.forEach((name) => {
      new cognito.CfnUserPoolGroup(this, `Group-${name}`, {
        groupName: name,
        userPoolId: userPool.userPoolId,
      });
    });

    // 可选：部署期间把某个用户加入 super_admin 组（初始化种子）
    // 注意：需要该用户已存在；并为当前部署角色授予 cognito-idp:AdminAddUserToGroup 权限
    const adminUsername = process.env.SEED_SUPER_ADMIN_USERNAME; // 可为空
    if (adminUsername) {
      const addToGroup = new cr.AwsCustomResource(this, 'SeedAdminToGroup', {
        onCreate: {
          service: 'CognitoIdentityServiceProvider',
          action: 'adminAddUserToGroup',
          parameters: {
            UserPoolId: userPool.userPoolId,
            Username: adminUsername,
            GroupName: 'super_admin',
          },
          physicalResourceId: cr.PhysicalResourceId.of(`Seed-${adminUsername}-super_admin`),
        },
        policy: cr.AwsCustomResourcePolicy.fromSdkCalls({ resources: cr.AwsCustomResourcePolicy.ANY_RESOURCE }),
      });
    }
  }
}
```

提示：
- 如果不想在 CDK 中写入成员关系，亦可在 `cdk deploy` 之后使用 AWS CLI 运行：
```bash
aws cognito-idp admin-add-user-to-group \
  --user-pool-id <POOL_ID> \
  --username <USERNAME> \
  --group-name super_admin
```

## 在当前模板中落地（快速复用建议）
在 `infrastructure/lib/linuo-aws-template-stack.ts` 中，`this.userPool` 创建之后添加以下片段，用 CloudFormation 资源一次性创建 5 个组。后续部署如不修改这段代码，CDK 不会对这些组做任何变更（无 diff 即无动作）。

```ts
// after: this.userPool = new cognito.UserPool(...)
const roleGroups = ['super_admin', 'admin', 'user', 'moderator', 'customer'];
roleGroups.forEach((name, i) => {
  const g = new cognito.CfnUserPoolGroup(this, `Group-${name}`, {
    userPoolId: this.userPool.userPoolId,
    groupName: name,
    precedence: i + 1, // 可选：控制多组优先级
  });
  // 建议：避免误删（销毁栈时保留 group）
  g.cfnOptions.deletionPolicy = cdk.CfnDeletionPolicy.RETAIN;
  g.cfnOptions.updateReplacePolicy = cdk.CfnDeletionPolicy.RETAIN;
});
```

注意事项：
- 保持逻辑 ID 稳定（如 `Group-super_admin`），避免后续改名引发替换操作。
- 若未来确需新增组，只需向数组中追加名称；已有组不会受影响。
- 用户加入组的动作不在此片段内完成；可在控制台、CLI 或使用上文的自定义资源在首次部署时注入一个 `super_admin` 用户。

## Claim 映射规范
- `userId` ← `sub`
- `email` ← `email`（注意：`access_token` 不一定包含 email；如需用户信息更丰富请验证 `id_token`）
- `groups` ← `cognito:groups`（string[]）
- `role` ← `custom:role`（如使用）
- 策略：优先按组 → 回退 `custom:role` → 默认为拒绝（不设置默认放行）。

## 监控与日志
- 指标：验证成功率/失败率、401/403 比例、刷新/登出成功率。
- 日志：失败原因（过期、签名错误、aud/iss/token_use 不匹配）、`kid` 命中情况。
- 告警：验证失败率 >2%（5 分钟窗口）触发。

## 安全要求
- 校验项（全部强制）：
  - `iss = https://cognito-idp.${region}.amazonaws.com/${userPoolId}`
  - `aud/client_id` 在允许的 `COGNITO_CLIENT_ID` 列表
  - `token_use` 等于配置的 `access` 或 `id`
  - `exp/nbf` 有效
- JWKS：启用缓存；网络/JWKS 失败严格拒绝（fail-closed）。
- 最小权限：IAM 仅授予必要的 Cognito API 权限。

## 测试方案
- 单元测试：
  - mock `aws-jwt-verify` 覆盖有效/过期/签名错误/aud/iss/token_use 不匹配场景。
  - `auth.service.login/refresh/logout`：断言对 Cognito 的命令与参数。
- 集成测试：
  - 使用测试池获取真实 token 调用受保护路由应 200。
  - 刷新/登出流程按预期响应。
- 回归测试：
  - 注册/验证/改密保持可用。

## 部署与切换（一次性全量）
- 步骤：
  1) 合并并部署上述代码改造；
  2) 替换配置，仅保留 `COGNITO_*`；
  3) 所有服务同步上线 `CognitoVerifier`；
  4) 客户端改为获取并携带 Cognito token（或使用 Hosted UI）。
- 注意：部署完成即全量生效，旧自签 token 将全部被拒绝（401）。

## 回滚策略
- 本方案不保留回滚与双栈路径。如需回退需通过代码回退并重新部署。

## 验收标准
- 仅凭 Cognito JWT 可访问所有受保护路由，旧自签 token 全部 401。
- 所有服务均无需共享对称密钥即可互认令牌。
- 安全扫描通过（无对称密钥分发），监控指标稳定。

## 时间线建议（加速版）
- 第1–2天：开发与联调（登录/刷新/登出、中间件、配置与测试）。
- 第3天：测试环境全量切换与验证。
- 第4–5天：生产环境一次性全量切换与观测。

## 参考实现（其他服务中间件示例）
> 依赖：`npm i aws-jwt-verify`

```ts
// auth/cognito-verifier.middleware.ts
import { NextFunction, Request, Response } from 'express';
import { CognitoJwtVerifier } from 'aws-jwt-verify';

const verifier = CognitoJwtVerifier.create({
  userPoolId: process.env.COGNITO_USER_POOL_ID!,
  tokenUse: (process.env.COGNITO_TOKEN_USE as 'access' | 'id') || 'access',
  clientId: process.env.COGNITO_CLIENT_ID!,
});

export async function cognitoAuth(req: Request, _res: Response, next: NextFunction) {
  try {
    const auth = req.headers.authorization || '';
    if (!auth.startsWith('Bearer ')) throw new Error('Missing Bearer token');
    const token = auth.slice(7);
    const payload = await verifier.verify(token);
    req['user'] = {
      userId: payload.sub,
      email: (payload as any).email,
      groups: (payload as any)['cognito:groups'],
      role: (payload as any)['custom:role'],
    };
    next();
  } catch (err) {
    next(err);
  }
}
```

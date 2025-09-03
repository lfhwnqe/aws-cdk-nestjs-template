import {
  Injectable,
  BadRequestException,
  ConflictException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  GlobalSignOutCommand,
  RevokeTokenCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import crypto from 'node:crypto';

import { CognitoService } from '../shared/services/cognito.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { VerifyRegistrationDto } from './dto/verify-registration.dto';
import { Role } from '../common/decorators/roles.decorator';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly cognitoClient: CognitoIdentityProviderClient;
  private readonly clientId: string;
  private readonly clientSecret?: string;

  constructor(
    private readonly configService: ConfigService,
    private readonly cognitoService: CognitoService,
  ) {
    const region = this.configService.get<string>('cognito.region');
    this.clientId = this.configService.get<string>('cognito.clientId');
    this.clientSecret = this.configService.get<string>('cognito.clientSecret');
    this.cognitoClient = new CognitoIdentityProviderClient({ region });
  }

  private computeSecretHash(username: string): string | undefined {
    if (!this.clientSecret || !this.clientId) return undefined;
    const hmac = crypto.createHmac('sha256', this.clientSecret);
    hmac.update(username + this.clientId);
    return hmac.digest('base64');
  }

  async login(dto: LoginDto) {
    try {
      const secretHash = this.computeSecretHash(dto.username);
      const res = await this.cognitoClient.send(
        new InitiateAuthCommand({
          ClientId: this.clientId,
          AuthFlow: 'USER_PASSWORD_AUTH',
          AuthParameters: {
            USERNAME: dto.username,
            PASSWORD: dto.password,
            ...(secretHash ? { SECRET_HASH: secretHash } : {}),
          },
        }),
      );

      const r = res.AuthenticationResult || {};
      return {
        accessToken: r.AccessToken,
        idToken: r.IdToken,
        refreshToken: r.RefreshToken,
        expiresIn: r.ExpiresIn,
        tokenType: r.TokenType,
      };
    } catch (error) {
      const name = (error && (error.name || (error as any).__type)) || '';
      if (name === 'NotAuthorizedException') {
        throw new UnauthorizedException('Invalid username or password');
      }
      if (name === 'UserNotConfirmedException') {
        throw new UnauthorizedException('User is not confirmed');
      }
      throw new BadRequestException('Login failed');
    }
  }

  async refresh(params: { refreshToken: string; username?: string }) {
    const { refreshToken, username } = params || ({} as any);
    if (!refreshToken) {
      throw new BadRequestException('Missing refresh token');
    }
    try {
      const needsSecret = !!this.clientSecret;
      let secretHash: string | undefined;
      if (needsSecret) {
        if (!username) {
          throw new BadRequestException(
            'Missing username for refresh with client secret',
          );
        }
        secretHash = this.computeSecretHash(username);
      }
      const res = await this.cognitoClient.send(
        new InitiateAuthCommand({
          ClientId: this.clientId,
          AuthFlow: 'REFRESH_TOKEN_AUTH',
          AuthParameters: {
            REFRESH_TOKEN: refreshToken,
            ...(needsSecret && username ? { USERNAME: username } : {}),
            ...(secretHash ? { SECRET_HASH: secretHash } : {}),
          },
        }),
      );
      const r = res.AuthenticationResult || {};
      return {
        accessToken: r.AccessToken,
        idToken: r.IdToken,
        expiresIn: r.ExpiresIn,
        tokenType: r.TokenType,
      };
    } catch (error) {
      const name = (error && (error.name || (error as any).__type)) || '';
      if (
        name === 'NotAuthorizedException' ||
        name === 'InvalidParameterException'
      ) {
        throw new UnauthorizedException('Invalid refresh token');
      }
      throw new BadRequestException('Refresh failed');
    }
  }

  async logout(params: { accessToken?: string; refreshToken?: string }) {
    const { accessToken, refreshToken } = params || {};
    if (!accessToken && !refreshToken) {
      throw new BadRequestException(
        'Either accessToken or refreshToken required',
      );
    }

    try {
      if (accessToken) {
        await this.cognitoClient.send(
          new GlobalSignOutCommand({ AccessToken: accessToken }),
        );
      }
    } catch (e) {
      // 忽略未登录等无害错误，继续尝试刷新令牌撤销
      this.logger.debug('GlobalSignOut skipped/failed: ' + (e as any)?.name);
    }

    try {
      if (refreshToken) {
        await this.cognitoClient.send(
          new RevokeTokenCommand({
            ClientId: this.clientId,
            ...(this.clientSecret ? { ClientSecret: this.clientSecret } : {}),
            Token: refreshToken,
          }),
        );
      }
    } catch (e) {
      this.logger.debug('RevokeToken skipped/failed: ' + (e as any)?.name);
    }

    return { success: true, message: 'Logged out' };
  }

  async register(registerDto: RegisterDto) {
    const username = registerDto.username?.trim();
    const email = registerDto.email?.trim();
    const password = registerDto.password;
    const firstName = registerDto.firstName?.trim();
    const lastName = registerDto.lastName?.trim();
    const isEmailLikeUsername = /.+@.+\..+/.test(username || '');
    this.logger.log(
      `Register input snapshot => username=${username}, email=${email}, isEmailLikeUsername=${isEmailLikeUsername}, firstName=${firstName}, lastName=${lastName}`,
    );
    if (isEmailLikeUsername) {
      this.logger.warn(
        'Username looks like an email. If User Pool uses email alias, Cognito SignUp may reject this.',
      );
    }
    // 后端校验拦截：当用户池启用了 email alias，禁止邮箱格式作为 Username
    const emailAliasEnabled = this.configService.get<boolean>(
      'cognito.emailAliasEnabled',
    );
    if (emailAliasEnabled && isEmailLikeUsername) {
      this.logger.warn(
        'Blocked registration: username is email-like while email alias is enabled.',
      );
      throw new BadRequestException(
        '用户名不能为邮箱格式（当前用户池启用了 email 作为别名）。请使用非邮箱的用户名，邮箱请填写在 email 字段。',
      );
    }
    // 规则：
    // - 第一个注册的用户默认授予 SUPER_ADMIN，并加入 super_admin 组
    // - 其他用户默认授予 USER，并加入 user 组
    let assignRole: Role = Role.USER;
    try {
      const listRes = await this.cognitoService.listUsers(1);
      const hasAnyUser = Array.isArray(listRes.Users) && listRes.Users.length > 0;
      assignRole = hasAnyUser ? Role.USER : Role.SUPER_ADMIN;
      this.logger.log(
        `Register flow role decision => hasAnyUser=${hasAnyUser}, assignRole=${assignRole}`,
      );
    } catch (e) {
      this.logger.warn(
        `ListUsers failed, fallback to USER role. reason=${String((e as any)?.name || e)}`,
      );
    }

    try {
      const res = await this.cognitoService.signUp(
        username,
        password,
        email,
        firstName,
        lastName,
      );

      // 注册成功后，尽力设置自定义属性并加入相应的组（不阻断注册流程）
      try {
        await this.cognitoService.updateUserAttributes(username, [
          { Name: 'custom:role', Value: assignRole },
        ]);
        this.logger.log(
          `Set user role success => username=${username}, role=${assignRole}`,
        );
      } catch (e) {
        this.logger.error(
          `Failed to set user role for ${username}: ${String((e as any)?.name || e)}`,
        );
      }

      try {
        const groupName = assignRole === Role.SUPER_ADMIN ? Role.SUPER_ADMIN : Role.USER;
        await this.cognitoService.adminAddUserToGroup(username, groupName);
        this.logger.log(
          `Added user to Cognito group => username=${username}, group=${groupName}`,
        );
      } catch (e) {
        this.logger.error(
          `Failed to add user ${username} to group: ${String((e as any)?.name || e)}`,
        );
      }

      return {
        userSub: res.UserSub,
        message:
          'Registration successful. Please check your email for verification code.',
        requiresVerification: true,
        assignedRole: assignRole,
      };
    } catch (error) {
      const name = (error && (error.name || (error as any).__type)) || '';
      const detail = (error as any)?.message || '';
      this.logger.error(
        `Cognito SignUp failed: ${name} - ${detail}; username=${username}, email=${email}, isEmailLikeUsername=${isEmailLikeUsername}`,
      );
      if (name === 'UsernameExistsException') {
        throw new ConflictException('Username already exists');
      }
      if (name === 'InvalidPasswordException') {
        throw new BadRequestException('Password does not meet policy');
      }
      if (name === 'InvalidParameterException') {
        // 在开发环境中返回更详细的提示，便于排查（例如 SecretHash 缺失/不匹配、属性不被允许等）
        const nodeEnv = this.configService.get<string>('nodeEnv');
        const msg =
          nodeEnv === 'production'
            ? 'Invalid registration parameters'
            : `Invalid registration parameters: ${detail}`;
        throw new BadRequestException(msg);
      }
      throw new BadRequestException('Registration failed');
    }
  }

  async verifyRegistration(verifyRegistrationDto: VerifyRegistrationDto) {
    const { username, verificationCode } = verifyRegistrationDto;
    try {
      await this.cognitoService.confirmSignUp(username, verificationCode);
      return { message: 'Email verification successful', verified: true };
    } catch (error) {
      const name = (error && (error.name || (error as any).__type)) || '';
      if (name === 'CodeMismatchException') {
        throw new BadRequestException('Invalid verification code');
      }
      if (name === 'ExpiredCodeException') {
        throw new BadRequestException('Verification code has expired');
      }
      if (name === 'UserNotFoundException') {
        throw new BadRequestException('User not found');
      }
      if (name === 'NotAuthorizedException') {
        throw new ConflictException('User is already verified');
      }
      if (name === 'LimitExceededException') {
        throw new BadRequestException('Too many attempts. Try later');
      }
      throw new BadRequestException('Verification failed');
    }
  }

  // 兼容客户模块：为客户创建/删除登录账号（仅对接 Cognito，不写本地密码）
  async registerCustomerAccount(
    username: string,
    password: string,
    email: string,
    firstName: string,
    lastName: string,
    customerId: string,
  ): Promise<void> {
    try {
      // 使用 Cognito 管理接口创建用户并设置密码
      await this.cognitoService.createUser(username, email, password);
      await this.cognitoService.setUserPassword(username, password, true);
      this.logger.log(
        `Cognito user created for customer ${customerId}: ${username}`,
      );
      // 注意：不在本地保存密码或用户敏感信息
    } catch (error) {
      const name = (error && (error.name || (error as any).__type)) || '';
      if (name === 'InvalidPasswordException') {
        throw new BadRequestException('密码不符合安全策略');
      }
      if (name === 'UsernameExistsException') {
        throw new ConflictException('用户名已存在');
      }
      if (name === 'InvalidParameterException') {
        throw new BadRequestException('注册参数无效');
      }
      throw new BadRequestException('创建客户账号失败');
    }
  }

  async deleteCustomerAccount(username: string): Promise<void> {
    this.logger.warn(`Rolling back customer account for username: ${username}`);
    try {
      await this.cognitoService.deleteUser(username);
    } catch (err) {
      this.logger.warn(
        `Rollback warning: failed to delete Cognito user ${username}`,
        err as any,
      );
    }
  }
}

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

import { CognitoService } from '../shared/services/cognito.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { VerifyRegistrationDto } from './dto/verify-registration.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly cognitoClient: CognitoIdentityProviderClient;
  private readonly clientId: string;

  constructor(
    private readonly configService: ConfigService,
    private readonly cognitoService: CognitoService,
  ) {
    const region = this.configService.get<string>('cognito.region');
    this.clientId = this.configService.get<string>('cognito.clientId');
    this.cognitoClient = new CognitoIdentityProviderClient({ region });
  }

  async login(dto: LoginDto) {
    try {
      const res = await this.cognitoClient.send(
        new InitiateAuthCommand({
          ClientId: this.clientId,
          AuthFlow: 'USER_PASSWORD_AUTH',
          AuthParameters: {
            USERNAME: dto.username,
            PASSWORD: dto.password,
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

  async refresh(refreshToken: string) {
    if (!refreshToken) {
      throw new BadRequestException('Missing refresh token');
    }
    try {
      const res = await this.cognitoClient.send(
        new InitiateAuthCommand({
          ClientId: this.clientId,
          AuthFlow: 'REFRESH_TOKEN_AUTH',
          AuthParameters: {
            REFRESH_TOKEN: refreshToken,
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
    const { username, email, password, firstName, lastName } = registerDto;
    try {
      const res = await this.cognitoService.signUp(
        username,
        password,
        email,
        firstName,
        lastName,
      );
      return {
        userSub: res.UserSub,
        message:
          'Registration successful. Please check your email for verification code.',
        requiresVerification: true,
      };
    } catch (error) {
      const name = (error && (error.name || (error as any).__type)) || '';
      if (name === 'UsernameExistsException') {
        throw new ConflictException('Username already exists');
      }
      if (name === 'InvalidPasswordException') {
        throw new BadRequestException('Password does not meet policy');
      }
      if (name === 'InvalidParameterException') {
        throw new BadRequestException('Invalid registration parameters');
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

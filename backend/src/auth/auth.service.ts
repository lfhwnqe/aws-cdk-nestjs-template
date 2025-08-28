import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcryptjs';

import { CognitoService } from '../shared/services/cognito.service';
import { DynamodbService } from '../database/dynamodb.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { VerifyRegistrationDto } from './dto/verify-registration.dto';
import { ChangePasswordDto } from './dto/change-password.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
    private cognitoService: CognitoService,
    private dynamodbService: DynamodbService,
  ) {}

  private translateCognitoPasswordError(error: any): string {
    const message = (error && (error.message || error.toString())) || '';
    // 基于 Cognito 返回的英文错误文案做映射
    if (/numeric/i.test(message) || /(\bdigit\b|\bnumbers?\b)/i.test(message)) {
      return '密码不符合安全策略：需包含数字';
    }
    if (/uppercase/i.test(message)) {
      return '密码不符合安全策略：需包含大写字母';
    }
    if (/lowercase/i.test(message)) {
      return '密码不符合安全策略：需包含小写字母';
    }
    if (/special character|symbol/i.test(message)) {
      return '密码不符合安全策略：需包含特殊字符';
    }
    if (/length|short/i.test(message)) {
      return '密码不符合安全策略：长度不满足要求';
    }
    return '密码不符合安全策略';
  }

  private isEmailFormat(username: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(username);
  }

  async validateUser(username: string, password: string): Promise<any> {
    try {
      // This is a simplified validation - in production, you'd integrate with Cognito properly
      const user = await this.dynamodbService.get('users', {
        userId: username,
      });

      if (user && (await bcrypt.compare(password, user.password))) {
        const { password, ...result } = user;
        return result;
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  async login(loginDto: LoginDto) {
    const user = await this.validateUser(loginDto.username, loginDto.password);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = {
      username: user.username,
      sub: user.userId,
      email: user.email,
      role: user.role || 'admin',
    };

    return {
      access_token: this.jwtService.sign(payload),
      user: {
        userId: user.userId,
        username: user.username,
        email: user.email,
        role: user.role || 'admin',
      },
    };
  }

  async register(registerDto: RegisterDto) {
    const { username, email, password, firstName, lastName } = registerDto;

    this.logger.log(
      `Attempting to register user: ${username} with email: ${email}`,
    );

    // Generate a unique username for Cognito if the provided username is an email
    // Cognito doesn't allow email format usernames when email aliases are enabled
    let cognitoUsername = username;
    if (this.isEmailFormat(username)) {
      // Generate a unique username based on email prefix and timestamp
      const emailPrefix = email.split('@')[0];
      const timestamp = Date.now().toString().slice(-6); // Last 6 digits of timestamp
      cognitoUsername = `${emailPrefix}_${timestamp}`;
    }

    // Check if user already exists in DynamoDB (using original username as userId)
    const existingUser = await this.dynamodbService.get('users', {
      userId: username,
    });
    if (existingUser) {
      throw new UnauthorizedException('User already exists');
    }

    try {
      // Create user in Cognito first (this will send verification email)
      const cognitoResult = await this.cognitoService.signUp(
        cognitoUsername,
        password,
        email,
        firstName,
        lastName,
      );

      this.logger.log(
        `Successfully created user in Cognito: ${cognitoUsername}, UserSub: ${cognitoResult.UserSub}`,
      );

      // Hash password for DynamoDB storage
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create user in DynamoDB with pending verification status
      const newUser = {
        userId: username, // Keep original username as userId for consistency
        username,
        cognitoUsername, // Store the Cognito username for future reference
        email,
        password: hashedPassword,
        firstName,
        lastName,
        role: 'admin',
        emailVerified: false,
        status: 'pending_verification', // 用户状态为待验证
        cognitoUserSub: cognitoResult.UserSub, // 存储Cognito用户ID
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      await this.dynamodbService.put('users', newUser);

      this.logger.log(`Successfully created user in DynamoDB: ${username}`);

      const { password: _, ...userResponse } = newUser;
      return {
        ...userResponse,
        message:
          'Registration successful. Please check your email for verification code.',
        requiresVerification: true,
      };
    } catch (error) {
      this.logger.error(`Failed to register user: ${username}`, error);

      // 处理 Cognito 注册错误
      if (error.name === 'UsernameExistsException') {
        throw new ConflictException('Username already exists');
      }

      if (error.name === 'InvalidPasswordException') {
        throw new BadRequestException(
          this.translateCognitoPasswordError(error),
        );
      }

      if (error.name === 'InvalidParameterException') {
        throw new BadRequestException('Invalid registration parameters');
      }

      // 通用错误处理
      this.logger.error(
        `Unexpected error during registration for user: ${username}`,
        error,
      );
      throw new BadRequestException('Registration failed. Please try again');
    }
  }

  async registerCustomerAccount(
    username: string,
    password: string,
    email: string,
    firstName: string,
    lastName: string,
    customerId: string,
  ) {
    this.logger.log(`Creating login for customer: ${username}`);

    const existingUser = await this.dynamodbService.get('users', {
      userId: username,
    });
    if (existingUser) {
      throw new ConflictException('User already exists');
    }

    try {
      await this.cognitoService.createUser(username, email, password);
      await this.cognitoService.setUserPassword(username, password, true);

      const hashedPassword = await bcrypt.hash(password, 10);
      const now = new Date().toISOString();

      await this.dynamodbService.put('users', {
        userId: username,
        username,
        email,
        password: hashedPassword,
        firstName,
        lastName,
        role: 'customer',
        customerId,
        emailVerified: true,
        status: 'active',
        createdAt: now,
        updatedAt: now,
      });
    } catch (error) {
      this.logger.error(
        `Failed to create customer account: ${username}`,
        error,
      );
      const name = (error && (error.name || (error as any).__type)) || '';
      if (name === 'InvalidPasswordException') {
        throw new BadRequestException(
          this.translateCognitoPasswordError(error),
        );
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

  async deleteCustomerAccount(username: string) {
    this.logger.warn(`Rolling back customer account for username: ${username}`);
    try {
      await this.cognitoService.deleteUser(username);
    } catch (err) {
      this.logger.warn(
        `Rollback warning: failed to delete Cognito user ${username}`,
        err,
      );
    }
    try {
      await this.dynamodbService.delete('users', { userId: username });
    } catch (err) {
      this.logger.warn(
        `Rollback warning: failed to delete user record ${username}`,
        err,
      );
    }
  }

  async getProfile(userId: string) {
    const user = await this.dynamodbService.get('users', { userId });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const { password, ...profile } = user;
    return profile;
  }

  async changePassword(userId: string, dto: ChangePasswordDto) {
    const { oldPassword, newPassword } = dto;

    // 读取用户，校验旧密码
    const user = await this.dynamodbService.get('users', { userId });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const match = await bcrypt.compare(oldPassword, user.password);
    if (!match) {
      throw new UnauthorizedException('旧密码不正确');
    }

    // 使用 Cognito 管理接口设置新密码（遵循密码策略校验）
    const cognitoUsername = user.cognitoUsername || user.username || userId;
    try {
      await this.cognitoService.setUserPassword(
        cognitoUsername,
        newPassword,
        true,
      );
    } catch (error) {
      // 将 Cognito 密码策略错误转为中文提示
      const name = (error && (error.name || (error as any).__type)) || '';
      if (name === 'InvalidPasswordException') {
        throw new BadRequestException(
          this.translateCognitoPasswordError(error),
        );
      }
      if (name === 'UserNotFoundException') {
        throw new BadRequestException('Cognito 中未找到该用户');
      }
      throw new BadRequestException('修改密码失败');
    }

    // 同步更新本地 DynamoDB 的密码哈希
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.dynamodbService.update(
      'users',
      { userId },
      'SET #pwd = :pwd, updatedAt = :updatedAt',
      {
        ':pwd': hashedPassword,
        ':updatedAt': new Date().toISOString(),
      },
      { '#pwd': 'password' },
    );

    return { message: '密码修改成功' };
  }

  async verifyRegistration(verifyRegistrationDto: VerifyRegistrationDto) {
    const { username, verificationCode } = verifyRegistrationDto;

    this.logger.log(`Attempting to verify registration for user: ${username}`);

    // Get user from DynamoDB to find the Cognito username
    const user = await this.dynamodbService.get('users', {
      userId: username,
    });

    if (!user) {
      throw new BadRequestException('User not found');
    }

    // Use the stored Cognito username for verification
    const cognitoUsername = user.cognitoUsername || username;

    try {
      // 调用 Cognito 确认用户注册
      await this.cognitoService.confirmSignUp(
        cognitoUsername,
        verificationCode,
      );

      this.logger.log(
        `Successfully verified registration for user: ${username}`,
      );

      // 更新 DynamoDB 中的用户状态为已验证
      try {
        await this.dynamodbService.put('users', {
          ...user,
          emailVerified: true,
          status: 'active',
          updatedAt: new Date().toISOString(),
        });

        this.logger.log(
          `Updated user status in DynamoDB for user: ${username}`,
        );
      } catch (dbError) {
        this.logger.warn(
          `Failed to update user status in DynamoDB for user: ${username}`,
          dbError,
        );
        // 不抛出错误，因为 Cognito 验证已成功
      }

      return {
        message: 'Email verification successful',
        verified: true,
      };
    } catch (error) {
      this.logger.error(
        `Failed to verify registration for user: ${username}`,
        error,
      );

      // 处理不同类型的 Cognito 错误
      if (error.name === 'CodeMismatchException') {
        throw new BadRequestException('Invalid verification code');
      }

      if (error.name === 'ExpiredCodeException') {
        throw new BadRequestException('Verification code has expired');
      }

      if (error.name === 'UserNotFoundException') {
        throw new BadRequestException('User not found');
      }

      if (error.name === 'NotAuthorizedException') {
        throw new ConflictException('User is already verified');
      }

      if (error.name === 'LimitExceededException') {
        throw new BadRequestException(
          'Too many attempts. Please try again later',
        );
      }

      // 处理其他 AWS 服务错误
      if (error.name === 'InvalidParameterException') {
        throw new BadRequestException('Invalid parameters provided');
      }

      // 通用错误处理
      this.logger.error(
        `Unexpected error during verification for user: ${username}`,
        error,
      );
      throw new BadRequestException('Verification failed. Please try again');
    }
  }
}

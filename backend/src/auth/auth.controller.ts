import { Controller, Post, Body, Logger } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { VerifyRegistrationDto } from './dto/verify-registration.dto';
import { Public } from '../common/decorators/public.decorator';
import { IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { CognitoService } from '../shared/services/cognito.service';
import { Role } from '../common/decorators/roles.decorator';
import { RefreshTokenDto } from './dto/refresh-token.dto';

class LogoutDto {
  @ApiProperty({ required: false, description: 'Cognito Access Token' })
  @IsString()
  @IsOptional()
  accessToken?: string;

  @ApiProperty({ required: false, description: 'Cognito Refresh Token' })
  @IsString()
  @IsOptional()
  refreshToken?: string;
}

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(AuthController.name);
  constructor(
    private readonly authService: AuthService,
    private readonly cognitoService: CognitoService,
  ) {}

  @Post('login')
  @Public()
  @ApiOperation({ summary: 'User login' })
  @ApiResponse({ status: 200, description: 'Login successful' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @Post('register')
  @Public()
  @ApiOperation({ summary: 'User registration' })
  @ApiResponse({ status: 201, description: 'User registered successfully' })
  @ApiResponse({ status: 400, description: 'Registration failed' })
  async register(@Body() registerDto: RegisterDto) {
    // 规则：
    // - 第一个注册的用户默认授予 super_admin
    // - 其他通过注册创建的用户默认授予 USER
    // 说明：通过更新 Cognito 自定义属性 custom:role 来承载角色信息

    // 判断是否为第一个用户（基于当前 User Pool 中用户数量）
    let assignRole: Role = Role.USER;
    try {
      const listRes = await this.cognitoService.listUsers(1);
      const hasAnyUser = Array.isArray(listRes.Users) && listRes.Users.length > 0;
      assignRole = hasAnyUser ? Role.USER : Role.SUPER_ADMIN;
      this.logger.log(
        `Register flow role decision => hasAnyUser=${hasAnyUser}, assignRole=${assignRole}`,
      );
    } catch (e) {
      // 如果查询失败，不阻断注册流程，仅记录日志，默认设置为 USER
      this.logger.warn(
        `ListUsers failed, fallback to USER role. reason=${String((e as any)?.name || e)}`,
      );
    }

    // 先执行注册
    this.logger.log(
      `Register attempt => username=${registerDto.username}, email=${registerDto.email}`,
    );
    const result = await this.authService.register(registerDto);

    // 注册成功后为该用户设置自定义角色属性
    try {
      await this.cognitoService.updateUserAttributes(registerDto.username, [
        { Name: 'custom:role', Value: assignRole },
      ]);
      this.logger.log(
        `Set user role success => username=${registerDto.username}, role=${assignRole}`,
      );
    } catch (e) {
      // 不影响注册返回，但输出日志，便于后续手动干预
      this.logger.error(
        `Failed to set user role for ${registerDto.username}: ${String(
          (e as any)?.name || e,
        )}`,
      );
    }

    return {
      ...result,
      assignedRole: assignRole,
    };
  }

  @Post('verify-registration')
  @Public()
  @ApiOperation({
    summary: 'Verify user registration with email verification code',
  })
  @ApiResponse({
    status: 200,
    description: 'Email verification successful',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        data: {
          type: 'object',
          properties: {
            message: {
              type: 'string',
              example: 'Email verification successful',
            },
            verified: { type: 'boolean', example: true },
          },
        },
        timestamp: { type: 'string', example: '2024-01-01T00:00:00.000Z' },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid verification code or user not found',
  })
  @ApiResponse({ status: 409, description: 'User is already verified' })
  async verifyRegistration(
    @Body() verifyRegistrationDto: VerifyRegistrationDto,
  ) {
    return this.authService.verifyRegistration(verifyRegistrationDto);
  }

  @Post('refresh')
  @Public()
  @ApiOperation({ summary: 'Refresh tokens via Cognito' })
  @ApiResponse({ status: 200, description: 'Tokens refreshed' })
  async refresh(@Body() dto: RefreshTokenDto) {
    return this.authService.refresh(dto);
  }

  @Post('logout')
  @Public()
  @ApiOperation({ summary: 'Logout (GlobalSignOut/RevokeToken)' })
  @ApiResponse({ status: 200, description: 'Logged out' })
  async logout(@Body() dto: LogoutDto) {
    return this.authService.logout(dto);
  }
}

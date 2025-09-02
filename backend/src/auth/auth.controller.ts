import { Controller, Post, Body } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { VerifyRegistrationDto } from './dto/verify-registration.dto';
import { Public } from '../common/decorators/public.decorator';
import { IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

class RefreshTokenDto {
  @ApiProperty({ description: 'Cognito Refresh Token' })
  @IsString()
  @IsNotEmpty()
  refreshToken: string;
}

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
  constructor(private readonly authService: AuthService) {}

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
    return this.authService.register(registerDto);
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
    return this.authService.refresh(dto.refreshToken);
  }

  @Post('logout')
  @Public()
  @ApiOperation({ summary: 'Logout (GlobalSignOut/RevokeToken)' })
  @ApiResponse({ status: 200, description: 'Logged out' })
  async logout(@Body() dto: LogoutDto) {
    return this.authService.logout(dto);
  }
}

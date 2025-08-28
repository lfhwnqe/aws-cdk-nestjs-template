import { Controller, Post, Body, Get } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';

import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { VerifyRegistrationDto } from './dto/verify-registration.dto';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { ChangePasswordDto } from './dto/change-password.dto';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @ApiOperation({ summary: 'User login' })
  @ApiResponse({ status: 200, description: 'Login successful' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @Post('register')
  @ApiOperation({ summary: 'User registration' })
  @ApiResponse({ status: 201, description: 'User registered successfully' })
  @ApiResponse({ status: 400, description: 'Registration failed' })
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Post('verify-registration')
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

  @Get('profile')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Get user profile' })
  @ApiResponse({ status: 200, description: 'Profile retrieved successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getProfile(@CurrentUser('userId') userId: string) {
    return this.authService.getProfile(userId);
  }

  @Post('change-password')
  @ApiBearerAuth('JWT-auth')
  @ApiOperation({ summary: 'Change password (Cognito)' })
  @ApiResponse({ status: 200, description: 'Password changed successfully' })
  @ApiResponse({ status: 400, description: 'Invalid new password' })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized or wrong old password',
  })
  async changePassword(
    @CurrentUser('userId') userId: string,
    @Body() dto: ChangePasswordDto,
  ) {
    return this.authService.changePassword(userId, dto);
  }
}

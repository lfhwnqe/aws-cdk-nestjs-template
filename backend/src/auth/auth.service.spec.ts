import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import {
  BadRequestException,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';

import { AuthService } from './auth.service';
import { CognitoService } from '../shared/services/cognito.service';
import { DynamodbService } from '../database/dynamodb.service';
import { VerifyRegistrationDto } from './dto/verify-registration.dto';
import { RegisterDto } from './dto/register.dto';

describe('AuthService', () => {
  let service: AuthService;
  let cognitoService: jest.Mocked<CognitoService>;
  let dynamodbService: jest.Mocked<DynamodbService>;
  let jwtService: jest.Mocked<JwtService>;
  let configService: jest.Mocked<ConfigService>;

  beforeEach(async () => {
    const mockCognitoService = {
      confirmSignUp: jest.fn(),
      signUp: jest.fn(),
    };

    const mockDynamodbService = {
      get: jest.fn(),
      put: jest.fn(),
    };

    const mockJwtService = {
      sign: jest.fn(),
    };

    const mockConfigService = {
      get: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: CognitoService, useValue: mockCognitoService },
        { provide: DynamodbService, useValue: mockDynamodbService },
        { provide: JwtService, useValue: mockJwtService },
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    cognitoService = module.get(CognitoService);
    dynamodbService = module.get(DynamodbService);
    jwtService = module.get(JwtService);
    configService = module.get(ConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('verifyRegistration', () => {
    const verifyDto: VerifyRegistrationDto = {
      username: 'testuser',
      verificationCode: '123456',
    };

    it('should successfully verify registration', async () => {
      const mockUser = {
        userId: 'testuser',
        username: 'testuser',
        email: 'test@example.com',
        emailVerified: false,
        status: 'pending_verification',
      };

      cognitoService.confirmSignUp.mockResolvedValue({});
      dynamodbService.get.mockResolvedValue(mockUser);
      dynamodbService.put.mockResolvedValue({});

      const result = await service.verifyRegistration(verifyDto);

      expect(cognitoService.confirmSignUp).toHaveBeenCalledWith(
        'testuser',
        '123456',
      );
      expect(dynamodbService.get).toHaveBeenCalledWith('users', {
        userId: 'testuser',
      });
      expect(dynamodbService.put).toHaveBeenCalledWith('users', {
        ...mockUser,
        emailVerified: true,
        status: 'active',
        updatedAt: expect.any(String),
      });
      expect(result).toEqual({
        message: 'Email verification successful',
        verified: true,
      });
    });

    it('should handle invalid verification code', async () => {
      const error = new Error('Invalid code');
      error.name = 'CodeMismatchException';
      cognitoService.confirmSignUp.mockRejectedValue(error);

      await expect(service.verifyRegistration(verifyDto)).rejects.toThrow(
        BadRequestException,
      );
      await expect(service.verifyRegistration(verifyDto)).rejects.toThrow(
        'Invalid verification code',
      );
    });

    it('should handle expired verification code', async () => {
      const error = new Error('Code expired');
      error.name = 'ExpiredCodeException';
      cognitoService.confirmSignUp.mockRejectedValue(error);

      await expect(service.verifyRegistration(verifyDto)).rejects.toThrow(
        BadRequestException,
      );
      await expect(service.verifyRegistration(verifyDto)).rejects.toThrow(
        'Verification code has expired',
      );
    });

    it('should handle user not found', async () => {
      const error = new Error('User not found');
      error.name = 'UserNotFoundException';
      cognitoService.confirmSignUp.mockRejectedValue(error);

      await expect(service.verifyRegistration(verifyDto)).rejects.toThrow(
        BadRequestException,
      );
      await expect(service.verifyRegistration(verifyDto)).rejects.toThrow(
        'User not found',
      );
    });

    it('should handle already verified user', async () => {
      const error = new Error('Already verified');
      error.name = 'NotAuthorizedException';
      cognitoService.confirmSignUp.mockRejectedValue(error);

      await expect(service.verifyRegistration(verifyDto)).rejects.toThrow(
        ConflictException,
      );
      await expect(service.verifyRegistration(verifyDto)).rejects.toThrow(
        'User is already verified',
      );
    });

    it('should handle too many attempts', async () => {
      const error = new Error('Too many attempts');
      error.name = 'LimitExceededException';
      cognitoService.confirmSignUp.mockRejectedValue(error);

      await expect(service.verifyRegistration(verifyDto)).rejects.toThrow(
        BadRequestException,
      );
      await expect(service.verifyRegistration(verifyDto)).rejects.toThrow(
        'Too many attempts. Please try again later',
      );
    });

    it('should continue even if DynamoDB update fails', async () => {
      const mockUser = {
        userId: 'testuser',
        username: 'testuser',
        email: 'test@example.com',
        emailVerified: false,
        status: 'pending_verification',
      };

      cognitoService.confirmSignUp.mockResolvedValue({});
      dynamodbService.get.mockResolvedValue(mockUser);
      dynamodbService.put.mockRejectedValue(new Error('DynamoDB error'));

      const result = await service.verifyRegistration(verifyDto);

      expect(result).toEqual({
        message: 'Email verification successful',
        verified: true,
      });
    });
  });

  describe('register', () => {
    const registerDto: RegisterDto = {
      username: 'testuser',
      email: 'test@example.com',
      password: 'TestPassword123!',
      firstName: 'Test',
      lastName: 'User',
    };

    it('should successfully register user', async () => {
      const mockCognitoResult = {
        UserSub: 'cognito-user-id-123',
      };

      dynamodbService.get.mockResolvedValue(null); // User doesn't exist
      cognitoService.signUp.mockResolvedValue(mockCognitoResult);
      dynamodbService.put.mockResolvedValue({});

      const result = await service.register(registerDto);

      expect(cognitoService.signUp).toHaveBeenCalledWith(
        'testuser',
        'TestPassword123!',
        'test@example.com',
        'Test',
        'User',
      );
      expect(dynamodbService.put).toHaveBeenCalledWith(
        'users',
        expect.objectContaining({
          userId: 'testuser',
          username: 'testuser',
          email: 'test@example.com',
          firstName: 'Test',
          lastName: 'User',
          role: 'user',
          emailVerified: false,
          status: 'pending_verification',
          cognitoUserSub: 'cognito-user-id-123',
        }),
      );
      expect(result.requiresVerification).toBe(true);
      expect(result.message).toContain('verification code');
    });

    it('should handle existing user', async () => {
      const existingUser = { userId: 'testuser' };
      dynamodbService.get.mockResolvedValue(existingUser);

      await expect(service.register(registerDto)).rejects.toThrow(
        UnauthorizedException,
      );
      await expect(service.register(registerDto)).rejects.toThrow(
        'User already exists',
      );
    });

    it('should handle username exists in Cognito', async () => {
      const error = new Error('Username exists');
      error.name = 'UsernameExistsException';

      dynamodbService.get.mockResolvedValue(null);
      cognitoService.signUp.mockRejectedValue(error);

      await expect(service.register(registerDto)).rejects.toThrow(
        ConflictException,
      );
      await expect(service.register(registerDto)).rejects.toThrow(
        'Username already exists',
      );
    });

    it('should handle invalid password', async () => {
      const error = new Error('Invalid password');
      error.name = 'InvalidPasswordException';

      dynamodbService.get.mockResolvedValue(null);
      cognitoService.signUp.mockRejectedValue(error);

      await expect(service.register(registerDto)).rejects.toThrow(
        BadRequestException,
      );
      await expect(service.register(registerDto)).rejects.toThrow(
        'Password does not meet requirements',
      );
    });
  });
});

import { plainToClass, Transform } from 'class-transformer';
import {
  IsEnum,
  IsNumber,
  IsString,
  validateSync,
  IsOptional,
} from 'class-validator';

enum Environment {
  Development = 'development',
  Production = 'production',
  Test = 'test',
}

class EnvironmentVariables {
  @IsEnum(Environment)
  NODE_ENV: Environment;

  @IsNumber()
  @Transform(({ value }) => parseInt(value, 10))
  PORT: number;

  @IsString()
  APP_NAME: string;

  // AWS Configuration
  @IsString()
  AWS_REGION: string;

  @IsString()
  @IsOptional()
  AWS_ACCESS_KEY_ID?: string;

  @IsString()
  @IsOptional()
  AWS_SECRET_ACCESS_KEY?: string;

  // S3 Configuration
  @IsString()
  S3_BUCKET_NAME: string;

  @IsString()
  S3_REGION: string;

  // Cognito Configuration
  @IsString()
  COGNITO_USER_POOL_ID: string;

  @IsString()
  COGNITO_CLIENT_ID: string;

  @IsString()
  COGNITO_REGION: string;

  // DynamoDB Configuration
  @IsString()
  DYNAMODB_REGION: string;

  @IsString()
  DYNAMODB_TABLE_PREFIX: string;

  // JWT Configuration
  @IsString()
  JWT_SECRET: string;

  @IsString()
  JWT_EXPIRES_IN: string;

  // Database Tables
  @IsString()
  DB_TABLE_USERS: string;

  @IsString()
  DB_TABLE_TRADES: string;

  @IsString()
  DB_TABLE_FILES: string;

  // API Configuration
  @IsString()
  API_PREFIX: string;

  @IsString()
  SWAGGER_TITLE: string;

  @IsString()
  SWAGGER_DESCRIPTION: string;

  @IsString()
  SWAGGER_VERSION: string;
}

export function validate(config: Record<string, unknown>) {
  const validatedConfig = plainToClass(EnvironmentVariables, config, {
    enableImplicitConversion: true,
  });

  const errors = validateSync(validatedConfig, {
    skipMissingProperties: false,
  });

  if (errors.length > 0) {
    throw new Error(errors.toString());
  }

  return validatedConfig;
}

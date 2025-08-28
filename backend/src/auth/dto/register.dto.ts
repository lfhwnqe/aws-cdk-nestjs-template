import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsEmail,
  IsNotEmpty,
  MinLength,
  Matches,
} from 'class-validator';

export class RegisterDto {
  @ApiProperty({
    description: 'Username',
    example: 'john_doe',
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(3)
  username: string;

  @ApiProperty({
    description: 'Email address',
    example: 'john@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    description:
      'Password (min 8 chars, must contain uppercase, lowercase, number, and special character)',
    example: 'Password123!',
    minLength: 8,
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message:
      'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
  })
  password: string;

  @ApiProperty({
    description: 'First name',
    example: 'John',
  })
  @IsString()
  @IsNotEmpty()
  firstName: string;

  @ApiProperty({
    description: 'Last name',
    example: 'Doe',
  })
  @IsString()
  @IsNotEmpty()
  lastName: string;
}

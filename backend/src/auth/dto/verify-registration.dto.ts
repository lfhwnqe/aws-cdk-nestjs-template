import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, Length, Matches } from 'class-validator';

export class VerifyRegistrationDto {
  @ApiProperty({
    description: 'Username or email address used during registration',
    example: 'john_doe',
  })
  @IsString()
  @IsNotEmpty()
  username: string;

  @ApiProperty({
    description: 'Verification code received via email',
    example: '123456',
    minLength: 6,
    maxLength: 6,
  })
  @IsString()
  @IsNotEmpty()
  @Length(6, 6, { message: 'Verification code must be exactly 6 characters' })
  @Matches(/^\d{6}$/, { message: 'Verification code must contain only digits' })
  verificationCode: string;
}

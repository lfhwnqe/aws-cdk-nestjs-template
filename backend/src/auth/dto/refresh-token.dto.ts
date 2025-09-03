import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class RefreshTokenDto {
  @ApiProperty({ description: 'Cognito Refresh Token' })
  @IsString()
  @IsNotEmpty()
  refreshToken: string;

  @ApiProperty({ description: 'Username used in Cognito' })
  @IsString()
  @IsNotEmpty()
  username: string;
}


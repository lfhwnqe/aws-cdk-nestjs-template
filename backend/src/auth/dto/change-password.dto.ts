import { ApiProperty } from '@nestjs/swagger';
import { IsString, MinLength } from 'class-validator';

export class ChangePasswordDto {
  @ApiProperty({ description: '当前密码（旧密码）' })
  @IsString()
  oldPassword: string;

  @ApiProperty({ description: '新密码（符合 Cognito 密码策略）', minLength: 8 })
  @IsString()
  @MinLength(8)
  newPassword: string;
}

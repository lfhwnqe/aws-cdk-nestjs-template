import { ApiProperty } from '@nestjs/swagger';
import { IsNumber, IsPositive } from 'class-validator';

export class ConfirmUploadDto {
  @ApiProperty({
    description: 'File size in bytes',
    example: 1024000,
  })
  @IsNumber()
  @IsPositive()
  size: number;
}

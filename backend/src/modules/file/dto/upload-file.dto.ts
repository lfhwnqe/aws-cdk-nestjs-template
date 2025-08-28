import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsOptional } from 'class-validator';

export class UploadFileDto {
  @ApiProperty({
    type: 'string',
    format: 'binary',
    description: 'File to upload',
  })
  file: any;

  @ApiProperty({
    description: 'File description',
    example: 'Trade report for Q1 2024',
    required: false,
  })
  @IsString()
  @IsOptional()
  description?: string;
}

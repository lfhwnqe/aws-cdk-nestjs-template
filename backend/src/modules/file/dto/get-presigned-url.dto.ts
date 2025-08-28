import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty } from 'class-validator';

export class GetPresignedUrlDto {
  @ApiProperty({
    description: 'File name',
    example: 'trade-report.pdf',
  })
  @IsString()
  @IsNotEmpty()
  fileName: string;

  @ApiProperty({
    description: 'Content type',
    example: 'application/pdf',
  })
  @IsString()
  @IsNotEmpty()
  contentType: string;
}

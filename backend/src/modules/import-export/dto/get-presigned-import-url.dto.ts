import { ApiProperty } from '@nestjs/swagger';
import { IsIn, IsNotEmpty, IsString } from 'class-validator';

export class GetPresignedImportUrlDto {
  @ApiProperty({ example: 'customers_2024-08-15.xlsx' })
  @IsString()
  @IsNotEmpty()
  fileName: string;

  @ApiProperty({
    example:
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    enum: [
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/vnd.ms-excel',
    ],
  })
  @IsString()
  @IsIn([
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-excel',
  ])
  contentType: string;

  @ApiProperty({
    example: 'customer',
    enum: ['customer', 'product', 'transaction'],
  })
  @IsString()
  @IsIn(['customer', 'product', 'transaction'])
  type: 'customer' | 'product' | 'transaction';
}

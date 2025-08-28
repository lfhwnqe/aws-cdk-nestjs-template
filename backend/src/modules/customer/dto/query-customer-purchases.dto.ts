import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';

export class QueryCustomerPurchasesDto {
  @ApiProperty({ description: '页码', required: false, example: 1, minimum: 1 })
  @IsOptional()
  @Type(() => Number)
  @Min(1)
  page?: number = 1;

  @ApiProperty({
    description: '每页数量',
    required: false,
    example: 10,
    minimum: 1,
    maximum: 100,
  })
  @IsOptional()
  @Type(() => Number)
  @Min(1)
  @Max(100)
  limit?: number = 10;

  @ApiProperty({ description: '按产品ID筛选', required: false })
  @IsOptional()
  @IsString()
  productId?: string;
}

export class CustomerPurchaseListResponse {
  @ApiProperty({ description: '记录列表', type: 'array' })
  data: any[];

  @ApiProperty({ description: '总数' })
  total: number;

  @ApiProperty({ description: '当前页码' })
  page: number;

  @ApiProperty({ description: '每页数量' })
  limit: number;

  @ApiProperty({ description: '总页数' })
  totalPages: number;
}

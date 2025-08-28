import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString, IsEnum, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';
import { ProductType, ProductStatus } from '../entities/product.entity';

export class QueryProductDto {
  @ApiProperty({ description: '页码', example: 1, required: false, minimum: 1 })
  @IsOptional()
  @Type(() => Number)
  @Min(1)
  page?: number = 1;

  @ApiProperty({
    description: '每页数量',
    example: 10,
    required: false,
    minimum: 1,
    maximum: 500,
  })
  @IsOptional()
  @Type(() => Number)
  @Min(1)
  @Max(500)
  limit?: number = 10;

  @ApiProperty({ description: '搜索关键词(产品名称)', required: false })
  @IsOptional()
  @IsString()
  search?: string;

  @ApiProperty({
    description: '产品类型筛选',
    enum: ProductType,
    required: false,
  })
  @IsOptional()
  @IsEnum(ProductType)
  productType?: ProductType;

  @ApiProperty({
    description: '产品状态筛选',
    enum: ProductStatus,
    required: false,
  })
  @IsOptional()
  @IsEnum(ProductStatus)
  status?: ProductStatus;

  @ApiProperty({
    description: '排序字段',
    required: false,
    enum: ['createdAt', 'updatedAt', 'productName'],
  })
  @IsOptional()
  @IsString()
  sortBy?: string = 'createdAt';

  @ApiProperty({
    description: '排序方向',
    required: false,
    enum: ['asc', 'desc'],
  })
  @IsOptional()
  @IsEnum(['asc', 'desc'])
  sortOrder?: 'asc' | 'desc' = 'desc';
}

export class ProductListResponse {
  @ApiProperty({ description: '产品列表', type: 'array' })
  data: any[];

  @ApiProperty({ description: '总数量', example: 100 })
  total: number;

  @ApiProperty({ description: '当前页码', example: 1 })
  page: number;

  @ApiProperty({ description: '每页数量', example: 10 })
  limit: number;

  @ApiProperty({ description: '总页数', example: 10 })
  totalPages: number;
}

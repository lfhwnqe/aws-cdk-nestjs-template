import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString, IsEnum, Min, Max } from 'class-validator';
import { Type } from 'class-transformer';
import { TransactionStatus } from '../entities/transaction.entity';

export class QueryTransactionDto {
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

  @ApiProperty({ description: '客户ID筛选', required: false })
  @IsOptional()
  @IsString()
  customerId?: string;

  @ApiProperty({ description: '产品ID筛选', required: false })
  @IsOptional()
  @IsString()
  productId?: string;

  @ApiProperty({
    description: '交易状态筛选',
    enum: TransactionStatus,
    required: false,
  })
  @IsOptional()
  @IsEnum(TransactionStatus)
  transactionStatus?: TransactionStatus;

  @ApiProperty({
    description: '排序字段',
    required: false,
    enum: ['createdAt', 'updatedAt'],
  })
  @IsOptional()
  @IsString()
  sortBy?: string = 'createdAt';

  @ApiProperty({
    description: '排序方式',
    required: false,
    enum: ['asc', 'desc'],
  })
  @IsOptional()
  @IsEnum(['asc', 'desc'])
  sortOrder?: 'asc' | 'desc' = 'desc';
}

export class TransactionListResponse {
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

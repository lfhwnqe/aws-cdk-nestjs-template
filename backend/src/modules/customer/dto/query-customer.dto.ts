import { ApiProperty } from '@nestjs/swagger';
import {
  IsOptional,
  IsString,
  IsEnum,
  IsNumberString,
  Min,
  Max,
} from 'class-validator';
import { Transform, Type } from 'class-transformer';
import { CustomerStatus, RiskLevel } from '../entities/customer.entity';

export class QueryCustomerDto {
  @ApiProperty({
    description: '页码',
    example: 1,
    required: false,
    minimum: 1,
  })
  @IsOptional()
  @Type(() => Number)
  @Min(1, { message: '页码必须大于0' })
  page?: number = 1;

  @ApiProperty({
    description: '每页数量',
    example: 10,
    required: false,
    minimum: 1,
    maximum: 100,
  })
  @IsOptional()
  @Type(() => Number)
  @Min(1, { message: '每页数量必须大于0' })
  @Max(500, { message: '每页数量不能超过500' })
  limit?: number = 10;

  @ApiProperty({
    description: '搜索关键词（支持姓名、邮箱、手机号搜索）',
    example: '张小明',
    required: false,
  })
  @IsOptional()
  @IsString({ message: '搜索关键词必须是字符串' })
  search?: string;

  @ApiProperty({
    description: '客户状态筛选',
    enum: CustomerStatus,
    example: CustomerStatus.ACTIVE,
    required: false,
  })
  @IsOptional()
  @IsEnum(CustomerStatus, { message: '请选择有效的客户状态' })
  status?: CustomerStatus;

  @ApiProperty({
    description: '风险承受等级筛选',
    enum: RiskLevel,
    example: RiskLevel.MEDIUM,
    required: false,
  })
  @IsOptional()
  @IsEnum(RiskLevel, { message: '请选择有效的风险承受等级' })
  riskLevel?: RiskLevel;

  @ApiProperty({
    description: '创建时间开始日期 (YYYY-MM-DD)',
    example: '2024-01-01',
    required: false,
  })
  @IsOptional()
  @IsString({ message: '开始日期必须是字符串' })
  startDate?: string;

  @ApiProperty({
    description: '创建时间结束日期 (YYYY-MM-DD)',
    example: '2024-12-31',
    required: false,
  })
  @IsOptional()
  @IsString({ message: '结束日期必须是字符串' })
  endDate?: string;

  @ApiProperty({
    description: '排序字段',
    example: 'createdAt',
    required: false,
    enum: ['createdAt', 'updatedAt', 'firstName', 'lastName'],
  })
  @IsOptional()
  @IsString({ message: '排序字段必须是字符串' })
  sortBy?: string = 'createdAt';

  @ApiProperty({
    description: '排序方向',
    example: 'desc',
    required: false,
    enum: ['asc', 'desc'],
  })
  @IsOptional()
  @IsEnum(['asc', 'desc'], { message: '排序方向必须是 asc 或 desc' })
  sortOrder?: 'asc' | 'desc' = 'desc';
}

export class CustomerListResponse {
  @ApiProperty({
    description: '客户列表',
    type: 'array',
  })
  data: any[];

  @ApiProperty({
    description: '总数量',
    example: 100,
  })
  total: number;

  @ApiProperty({
    description: '当前页码',
    example: 1,
  })
  page: number;

  @ApiProperty({
    description: '每页数量',
    example: 10,
  })
  limit: number;

  @ApiProperty({
    description: '总页数',
    example: 10,
  })
  totalPages: number;
}

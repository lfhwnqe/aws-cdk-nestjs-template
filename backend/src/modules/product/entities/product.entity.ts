import { ApiProperty } from '@nestjs/swagger';
import { RiskLevel } from '../../customer/entities/customer.entity';

export enum ProductStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  SUSPENDED = 'suspended',
}

export enum ProductType {
  WEALTH = '理财',
  FUND = '基金',
  BOND = '债券',
  INSURANCE = '保险',
}

export class Product {
  @ApiProperty({ description: '产品ID', example: 'prod_123456' })
  productId: string;

  @ApiProperty({ description: '产品名称', example: '稳健理财产品' })
  productName: string;

  @ApiProperty({
    description: '产品类型',
    enum: ProductType,
    example: ProductType.WEALTH,
  })
  productType: ProductType;

  @ApiProperty({ description: '产品描述', required: false })
  description?: string;

  @ApiProperty({
    description: '风险等级',
    enum: RiskLevel,
    example: RiskLevel.MEDIUM,
  })
  riskLevel: RiskLevel;

  @ApiProperty({ description: '最低投资金额', example: 1000 })
  minInvestment: number;

  @ApiProperty({ description: '最高投资金额', example: 100000 })
  maxInvestment: number;

  @ApiProperty({ description: '预期年化收益率(%)', example: 5 })
  expectedReturn: number;

  @ApiProperty({ description: '结息日期', example: '每月' })
  interestPaymentDate: string;

  @ApiProperty({ description: '产品期限(天)', example: 365 })
  maturityPeriod: number;

  @ApiProperty({
    description: '产品状态',
    enum: ProductStatus,
    example: ProductStatus.ACTIVE,
  })
  status: ProductStatus;

  @ApiProperty({ description: '销售开始日期', example: '2024-01-01' })
  salesStartDate: string;

  @ApiProperty({ description: '销售结束日期', example: '2024-12-31' })
  salesEndDate: string;

  @ApiProperty({ description: '创建时间', example: '2024-01-01T00:00:00.000Z' })
  createdAt: string;

  @ApiProperty({ description: '更新时间', example: '2024-01-01T00:00:00.000Z' })
  updatedAt: string;

  @ApiProperty({ description: '创建者用户ID', example: 'user_123' })
  createdBy: string;
}

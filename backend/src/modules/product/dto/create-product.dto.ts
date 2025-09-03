import { ApiProperty } from '@nestjs/swagger';
import {
  IsString,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsNumber,
  Min,
  Max,
} from 'class-validator';
import { ProductType, ProductStatus, RiskLevel } from '../entities/product.entity';

export class CreateProductDto {
  @ApiProperty({ description: '产品名称', example: '稳健理财产品' })
  @IsString({ message: '产品名称必须是字符串' })
  @IsNotEmpty({ message: '产品名称不能为空' })
  productName: string;

  @ApiProperty({ description: '产品类型', enum: ProductType })
  @IsEnum(ProductType, { message: '请选择有效的产品类型' })
  productType: ProductType;

  @ApiProperty({ description: '产品描述', required: false })
  @IsString({ message: '产品描述必须是字符串' })
  @IsOptional()
  description?: string;

  @ApiProperty({ description: '风险等级', enum: RiskLevel })
  @IsEnum(RiskLevel, { message: '请选择有效的风险等级' })
  riskLevel: RiskLevel;

  @ApiProperty({ description: '最低投资金额', example: 1000 })
  @IsNumber({}, { message: '最低投资金额必须是数字' })
  @Min(0)
  minInvestment: number;

  @ApiProperty({ description: '最高投资金额', example: 100000 })
  @IsNumber({}, { message: '最高投资金额必须是数字' })
  @Min(0)
  maxInvestment: number;

  @ApiProperty({ description: '预期年化收益率(%)', example: 5 })
  @IsNumber({}, { message: '预期收益率必须是数字' })
  expectedReturn: number;

  @ApiProperty({ description: '结息日期', example: '每月' })
  @IsString()
  interestPaymentDate: string;

  @ApiProperty({ description: '产品期限(天)', example: 365 })
  @IsNumber({}, { message: '产品期限必须是数字' })
  @Min(0)
  maturityPeriod: number;

  @ApiProperty({
    description: '产品状态',
    enum: ProductStatus,
    required: false,
  })
  @IsEnum(ProductStatus, { message: '请选择有效的产品状态' })
  @IsOptional()
  status?: ProductStatus = ProductStatus.ACTIVE;

  @ApiProperty({ description: '销售开始日期', example: '2024-01-01' })
  @IsString()
  salesStartDate: string;

  @ApiProperty({ description: '销售结束日期', example: '2024-12-31' })
  @IsString()
  salesEndDate: string;
}

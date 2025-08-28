import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsEnum, IsNumber, IsOptional, Min } from 'class-validator';
import {
  TransactionType,
  TransactionStatus,
  PaymentMethod,
} from '../entities/transaction.entity';

export class CreateTransactionDto {
  @ApiProperty({ description: '客户ID' })
  @IsString()
  customerId: string;

  @ApiProperty({ description: '产品ID' })
  @IsString()
  productId: string;

  @ApiProperty({ description: '交易类型', enum: TransactionType })
  @IsEnum(TransactionType)
  transactionType: TransactionType;

  @ApiProperty({ description: '数量' })
  @IsNumber()
  @Min(0)
  quantity: number;

  @ApiProperty({ description: '单价' })
  @IsNumber()
  @Min(0)
  unitPrice: number;

  @ApiProperty({ description: '总金额', required: false })
  @IsNumber()
  @Min(0)
  @IsOptional()
  totalAmount?: number;

  @ApiProperty({
    description: '交易状态',
    enum: TransactionStatus,
    required: false,
  })
  @IsEnum(TransactionStatus)
  @IsOptional()
  transactionStatus?: TransactionStatus = TransactionStatus.PENDING;

  @ApiProperty({ description: '支付方式', enum: PaymentMethod })
  @IsEnum(PaymentMethod)
  paymentMethod: PaymentMethod;

  @ApiProperty({ description: '预期到期日期', required: false })
  @IsString()
  @IsOptional()
  expectedMaturityDate?: string;

  @ApiProperty({ description: '实际收益率', required: false })
  @IsNumber()
  @IsOptional()
  actualReturnRate?: number;

  @ApiProperty({ description: '备注信息', required: false })
  @IsString()
  @IsOptional()
  notes?: string;

  @ApiProperty({ description: '完成时间', required: false })
  @IsString()
  @IsOptional()
  completedAt?: string;
}

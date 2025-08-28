import { ApiProperty } from '@nestjs/swagger';

export enum TransactionType {
  PURCHASE = 'purchase',
  REDEEM = 'redeem',
}

export enum TransactionStatus {
  PENDING = 'pending',
  CONFIRMED = 'confirmed',
  COMPLETED = 'completed',
  CANCELLED = 'cancelled',
}

export enum PaymentMethod {
  BANK_TRANSFER = 'bank_transfer',
  CARD = 'card',
  OTHER = 'other',
}

export class Transaction {
  @ApiProperty({ description: '交易ID' })
  transactionId: string;

  @ApiProperty({ description: '客户ID' })
  customerId: string;

  @ApiProperty({ description: '产品ID' })
  productId: string;

  @ApiProperty({ description: '交易类型', enum: TransactionType })
  transactionType: TransactionType;

  @ApiProperty({ description: '数量' })
  quantity: number;

  @ApiProperty({ description: '单价' })
  unitPrice: number;

  @ApiProperty({ description: '总金额' })
  totalAmount: number;

  @ApiProperty({ description: '交易状态', enum: TransactionStatus })
  transactionStatus: TransactionStatus;

  @ApiProperty({ description: '支付方式', enum: PaymentMethod })
  paymentMethod: PaymentMethod;

  @ApiProperty({ description: '预期到期日期', required: false })
  expectedMaturityDate?: string;

  @ApiProperty({ description: '实际收益率', required: false })
  actualReturnRate?: number;

  @ApiProperty({ description: '备注信息', required: false })
  notes?: string;

  @ApiProperty({ description: '创建时间' })
  createdAt: string;

  @ApiProperty({ description: '更新时间' })
  updatedAt: string;

  @ApiProperty({ description: '完成时间', required: false })
  completedAt?: string;

  @ApiProperty({ description: '客户姓名（姓+名）', required: false })
  customerName?: string;

  @ApiProperty({ description: '产品名称', required: false })
  productName?: string;
}

import { PartialType } from '@nestjs/mapped-types';
import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';
import { CreateTransactionDto } from './create-transaction.dto';

export class UpdateTransactionDto extends PartialType(CreateTransactionDto) {
  @ApiProperty({ description: '交易ID', required: false })
  @IsString()
  @IsOptional()
  transactionId?: string;
}

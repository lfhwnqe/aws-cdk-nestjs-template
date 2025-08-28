import { Module } from '@nestjs/common';
import { DatabaseModule } from '../../database/database.module';
import { TransactionService } from './transaction.service';
import { TransactionController } from './transaction.controller';

@Module({
  imports: [DatabaseModule],
  providers: [TransactionService],
  controllers: [TransactionController],
  exports: [TransactionService],
})
export class TransactionModule {}

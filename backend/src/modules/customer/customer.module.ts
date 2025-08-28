import { Module } from '@nestjs/common';
import { CustomerService } from './customer.service';
import { CustomerController } from './customer.controller';
import { CustomerPurchasesController } from './customer-purchases.controller';
import { CustomerPurchasesService } from './customer-purchases.service';
import { DatabaseModule } from '../../database/database.module';
import { AuthModule } from '../../auth/auth.module';
import { ImportExportModule } from '@/modules/import-export/import-export.module';

@Module({
  imports: [DatabaseModule, AuthModule, ImportExportModule],
  // 将 CustomerPurchasesController 放在前面，避免被 CustomerController 的 `:id` 动态路由抢占
  controllers: [CustomerPurchasesController, CustomerController],
  providers: [CustomerService, CustomerPurchasesService],
  exports: [CustomerService],
})
export class CustomerModule {}

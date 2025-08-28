import { Module } from '@nestjs/common';
import { DatabaseModule } from '../../database/database.module';
import { ProductService } from './product.service';
import { ProductController } from './product.controller';

@Module({
  imports: [DatabaseModule],
  providers: [ProductService],
  controllers: [ProductController],
  exports: [ProductService],
})
export class ProductModule {}

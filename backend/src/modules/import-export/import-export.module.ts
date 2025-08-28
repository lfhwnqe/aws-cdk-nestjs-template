import { Global, Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ExportService } from './export.service';
import { ImportService } from './import.service';
import { ImportController } from './import.controller';

// 标记为全局模块，方便其他模块直接注入使用
@Global()
@Module({
  imports: [ConfigModule],
  controllers: [ImportController],
  providers: [ExportService, ImportService],
  exports: [ExportService, ImportService],
})
export class ImportExportModule {}

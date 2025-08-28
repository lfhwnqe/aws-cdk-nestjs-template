import { Module } from '@nestjs/common';
import { DatabaseModule } from '../../database/database.module';
import { StatsService } from './stats.service';
import { StatsController } from './stats.controller';

@Module({
  imports: [DatabaseModule],
  providers: [StatsService],
  controllers: [StatsController],
  exports: [StatsService],
})
export class StatsModule {}

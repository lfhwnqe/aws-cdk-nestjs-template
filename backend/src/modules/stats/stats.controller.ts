import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiQuery,
  ApiTags,
} from '@nestjs/swagger';
import { Roles, Role } from '../../common/decorators/roles.decorator';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { StatsService, SummaryStats, HistoryEntry } from './stats.service';

@ApiTags('Statistics')
@ApiBearerAuth('JWT-auth')
@UseGuards(RolesGuard)
@Controller('stats')
export class StatsController {
  constructor(private readonly statsService: StatsService) {}

  @Get('summary')
  @Roles(Role.ADMIN, Role.SUPER_ADMIN)
  @ApiOperation({ summary: '获取统计汇总' })
  async getSummary(): Promise<SummaryStats> {
    return this.statsService.getSummary();
  }

  @Get('history')
  @Roles(Role.ADMIN, Role.SUPER_ADMIN)
  @ApiOperation({ summary: '按时间维度获取历史统计' })
  @ApiQuery({
    name: 'granularity',
    required: false,
    enum: ['day', 'month'],
    description: '时间粒度，默认按月',
  })
  async getHistory(
    @Query('granularity') granularity: 'day' | 'month' = 'month',
  ): Promise<HistoryEntry[]> {
    return this.statsService.getHistory(granularity);
  }
}

import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { AppService } from './app.service';
import { Public } from './common/decorators/public.decorator';

@ApiTags('Application')
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Public()
  @Get()
  @ApiOperation({ summary: 'Get application info' })
  @ApiResponse({ status: 200, description: 'Application information' })
  getHello(): any {
    return this.appService.getHello();
  }

  @Public()
  @Get('health')
  @ApiOperation({ summary: 'Health check' })
  @ApiResponse({ status: 200, description: 'Health status' })
  getHealth(): any {
    return this.appService.getHealth();
  }
}

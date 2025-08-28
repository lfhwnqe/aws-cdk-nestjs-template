import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AppService {
  constructor(private configService: ConfigService) {}

  getHello(): any {
    return {
      message: 'Welcome to Trade Management API',
      version: '1.0.0',
      environment: this.configService.get<string>('NODE_ENV'),
      timestamp: new Date().toISOString(),
    };
  }

  getHealth(): any {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: this.configService.get<string>('NODE_ENV'),
      version: '1.0.0',
    };
  }
}

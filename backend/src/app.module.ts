import {
  Module,
  NestModule,
  MiddlewareConsumer,
  RequestMethod,
} from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';

import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { FileModule } from './modules/file/file.module';
import { CustomerModule } from './modules/customer/customer.module';
import { ProductModule } from './modules/product/product.module';
import { TransactionModule } from './modules/transaction/transaction.module';
import { StatsModule } from './modules/stats/stats.module';
import { DatabaseModule } from './database/database.module';
import { SharedModule } from './shared/shared.module';
import { ImportExportModule } from './modules/import-export/import-export.module';
import { AuthMiddleware } from './auth/middleware/auth.middleware';
import configuration from './config/configuration';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      envFilePath: ['.env.local', '.env'],
    }),
    JwtModule.registerAsync({
      global: true,
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('jwt.secret'),
        signOptions: {
          expiresIn: configService.get<string>('jwt.expiresIn'),
        },
      }),
      inject: [ConfigService],
    }),
    DatabaseModule,
    SharedModule,
    ImportExportModule,
    AuthModule,
    FileModule,
    CustomerModule,
    ProductModule,
    TransactionModule,
    StatsModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(AuthMiddleware)
      .exclude(
        // 认证相关路由
        { path: 'auth/login', method: RequestMethod.POST },
        { path: 'auth/register', method: RequestMethod.POST },
        { path: 'auth/verify-registration', method: RequestMethod.POST },
        // 应用基础路由
        { path: '', method: RequestMethod.GET },
        { path: 'health', method: RequestMethod.GET },
        // API 文档路由
        { path: 'docs', method: RequestMethod.GET },
        { path: 'docs/(.*)', method: RequestMethod.GET },
        // 如果有 svg-parser 相关路由，可以在这里添加
        // { path: 'svg-parser/parse', method: RequestMethod.POST },
        // { path: 'svg-parser/parse-string', method: RequestMethod.POST },
        // { path: 'svg-parser/parse-url', method: RequestMethod.POST },
        // { path: 'svg-parser/parse-file', method: RequestMethod.POST },
        // { path: 'svg-parser/validate', method: RequestMethod.POST },
        // 如果有 mindmap 相关路由，可以在这里添加
        // { path: 'mindmap', method: RequestMethod.GET },
      )
      .forRoutes('*');
  }
}

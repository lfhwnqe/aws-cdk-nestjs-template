import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Context,
} from 'aws-lambda';
const serverlessExpress = require('@vendia/serverless-express');
import helmet from 'helmet';
import * as compression from 'compression';
import * as cors from 'cors';

import { AppModule } from './app.module';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { TransformInterceptor } from './common/interceptors/transform.interceptor';
import { LoggingInterceptor } from './common/interceptors/logging.interceptor';

let cachedServer: any;

async function createNestApp() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  // Security middleware
  app.use(helmet());
  app.use(compression());
  app.use(
    cors({
      origin: true,
      credentials: true,
    }),
  );

  // Global prefix
  const apiPrefix = configService.get<string>('API_PREFIX', 'api/v1');
  app.setGlobalPrefix(apiPrefix);

  // Global pipes
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  // Global filters
  app.useGlobalFilters(new HttpExceptionFilter());

  // Global interceptors
  app.useGlobalInterceptors(
    new LoggingInterceptor(),
    new TransformInterceptor(),
  );

  // Swagger configuration (only when explicitly enabled)
  if (configService.get<string>('SWAGGER_ENABLED') === 'true') {
    const { SwaggerModule, DocumentBuilder } = await import('@nestjs/swagger');
    const config = new DocumentBuilder()
      .setTitle(
        configService.get<string>('SWAGGER_TITLE', 'Trade Management API'),
      )
      .setDescription(
        configService.get<string>(
          'SWAGGER_DESCRIPTION',
          'API for Trade Management System',
        ),
      )
      .setVersion(configService.get<string>('SWAGGER_VERSION', '1.0.0'))
      .addBearerAuth(
        {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          name: 'JWT',
          description: 'Enter JWT token',
          in: 'header',
        },
        'JWT-auth',
      )
      .build();

    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup(`${apiPrefix}/docs`, app, document, {
      // 关键：使用相对路径，避免 API Gateway stage（/dev）导致的绝对路径丢失
      swaggerUrl: './docs-json',
      swaggerOptions: {
        persistAuthorization: true,
      },
    });
  }

  await app.init();
  return app.getHttpAdapter().getInstance();
}

export const handler = async (
  event: APIGatewayProxyEvent,
  context: Context,
): Promise<APIGatewayProxyResult> => {
  if (!cachedServer) {
    const nestApp = await createNestApp();
    cachedServer = serverlessExpress({ app: nestApp });
  }

  return cachedServer(event, context);
};

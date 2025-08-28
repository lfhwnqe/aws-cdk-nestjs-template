import { Module, Global } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';

import { DynamodbService } from './dynamodb.service';

@Global()
@Module({
  imports: [ConfigModule],
  providers: [
    {
      provide: 'DYNAMODB_CLIENT',
      useFactory: (configService: ConfigService) => {
        // 优先使用 DynamoDB 专用 region，其次回退到全局 AWS region
        const region =
          configService.get<string>('dynamodb.region') ||
          configService.get<string>('aws.region');

        // AWS SDK will automatically use:
        // - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) for local development
        // - IAM roles when running in Lambda/EC2
        // - AWS CLI credentials as fallback
        const client = new DynamoDBClient({
          region,
        });
        return DynamoDBDocumentClient.from(client);
      },
      inject: [ConfigService],
    },
    DynamodbService,
  ],
  exports: ['DYNAMODB_CLIENT', DynamodbService],
})
export class DatabaseModule {}

import { Module, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { S3Service } from './services/s3.service';
import { CognitoService } from './services/cognito.service';

@Global()
@Module({
  imports: [ConfigModule],
  providers: [S3Service, CognitoService],
  exports: [S3Service, CognitoService],
})
export class SharedModule {}

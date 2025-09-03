import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { RolesGuard } from './guards/roles.guard';
import { CognitoService } from '../shared/services/cognito.service';

@Module({
  imports: [ConfigModule],
  controllers: [AuthController],
  providers: [AuthService, RolesGuard, CognitoService],
  exports: [AuthService, RolesGuard, CognitoService],
})
export class AuthModule {}

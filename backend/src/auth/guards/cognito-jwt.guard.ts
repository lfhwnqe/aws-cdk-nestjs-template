import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CognitoJwtVerifier } from 'aws-jwt-verify';

@Injectable()
export class CognitoJwtAuthGuard implements CanActivate {
  private readonly verifier: ReturnType<typeof CognitoJwtVerifier.create>;

  constructor(private readonly configService: ConfigService) {
    const userPoolId = this.configService.get<string>('cognito.userPoolId');
    const clientId = this.configService.get<string>('cognito.clientId');
    if (!userPoolId || !clientId) {
      throw new Error('Cognito configuration missing (userPoolId/clientId)');
    }
    this.verifier = CognitoJwtVerifier.create({
      userPoolId,
      clientId,
      tokenUse: 'access',
    });
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const auth =
      request.headers['authorization'] || request.headers['Authorization'];
    if (!auth || typeof auth !== 'string') {
      throw new UnauthorizedException('Missing Authorization header');
    }

    const parts = auth.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      throw new UnauthorizedException('Invalid Authorization header');
    }

    const token = parts[1];
    try {
      const claims = await this.verifier.verify(token);
      request.user = {
        userId: claims.sub,
        username:
          (claims as any).username ||
          (claims as any)['cognito:username'] ||
          (claims as any).email,
        email: (claims as any).email,
        groups: ((claims as any)['cognito:groups'] as string[]) || [],
        role: (claims as any)['custom:role'] || (claims as any).role,
        claims,
      };
      return true;
    } catch (e) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}

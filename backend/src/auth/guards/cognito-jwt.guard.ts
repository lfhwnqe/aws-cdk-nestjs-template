import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import { CognitoJwtVerifier } from 'aws-jwt-verify';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';

@Injectable()
export class CognitoJwtAuthGuard implements CanActivate {
  private readonly verifier: ReturnType<typeof CognitoJwtVerifier.create>;

  constructor(
    private readonly configService: ConfigService,
    private readonly reflector: Reflector,
  ) {
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
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    const request = context.switchToHttp().getRequest();
    const method: string = request.method || '';
    const path: string = (request.originalUrl || request.url || '').toString();

    // Allow Swagger and CORS preflight without decoration
    if (
      method === 'OPTIONS' ||
      /(^|\/)docs(\/|$)/.test(path) ||
      /(^|\/)docs-json$/.test(path)
    ) {
      return true;
    }
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

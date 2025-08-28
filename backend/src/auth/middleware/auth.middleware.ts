import {
  Injectable,
  NestMiddleware,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async use(req: Request, res: Response, next: NextFunction) {
    try {
      // 从请求头中提取 JWT 令牌
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new UnauthorizedException(
          'Missing or invalid authorization header',
        );
      }

      const token = authHeader.substring(7); // 移除 'Bearer ' 前缀

      // 验证 JWT 令牌
      const payload = await this.jwtService.verifyAsync(token, {
        secret: this.configService.get<string>('jwt.secret'),
      });

      // 将用户信息附加到请求对象
      req['user'] = {
        userId: payload.sub,
        username: payload.username,
        email: payload.email,
        role: payload.role,
      };

      next();
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}

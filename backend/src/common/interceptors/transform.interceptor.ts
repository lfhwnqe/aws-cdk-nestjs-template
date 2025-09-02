import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

export interface Response<T> {
  success: boolean;
  data: T;
  message?: string;
  timestamp: string;
}

@Injectable()
export class TransformInterceptor<T>
  implements NestInterceptor<T, Response<T>>
{
  intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Observable<Response<T>> {
    // 跳过 Swagger 文档与其静态资源，避免破坏返回的 HTML/JS/JSON
    if (context.getType() === 'http') {
      const req = context.switchToHttp().getRequest();
      const url: string = req.url || '';
      // if (url.includes('/docs') || url.includes('/docs-json')) {
      //   return next.handle() as any;
      // }
    }

    return next.handle().pipe(
      map((data) => ({
        success: true,
        data,
        timestamp: new Date().toISOString(),
      })),
    );
  }
}

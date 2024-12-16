import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { throwError } from 'rxjs';

@Injectable()
export class LoggerInterceptor implements NestInterceptor {
  private readonly logger = new Logger('HTTP');

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const { method, url } = request;
    const startTime = Date.now();

    return next.handle().pipe(
      tap(() => {
        const responseTime = Date.now() - startTime;
        this.logger.log(`✅ [SUCCESS] ${method} ${url} ${responseTime}ms`);
      }),
      catchError((error) => {
        const responseTime = Date.now() - startTime;
        this.logger.error(`❌ [ERROR] ${method} ${url} ${responseTime}ms`);
        return throwError(() => error);
      }),
    );
  }
}

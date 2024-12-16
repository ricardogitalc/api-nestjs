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
    const { method, url, body, headers } = request;
    const startTime = Date.now();

    return next.handle().pipe(
      tap((response) => {
        const endTime = Date.now();
        const responseTime = endTime - startTime;

        this.logger.log(
          `[SUCCESS] ${method} ${url} ${responseTime}ms\n` +
            `Headers: ${JSON.stringify(headers)}\n` +
            `Request Body: ${JSON.stringify(body)}\n` +
            `Response: ${JSON.stringify(response)}`,
        );
      }),
      catchError((error) => {
        const endTime = Date.now();
        const responseTime = endTime - startTime;

        this.logger.error(
          `[ERROR] ${method} ${url} ${responseTime}ms\n` +
            `Headers: ${JSON.stringify(headers)}\n` +
            `Request Body: ${JSON.stringify(body)}\n` +
            `Error: ${JSON.stringify({
              message: error.message,
              statusCode: error.status || error.statusCode,
              response: error.response,
            })}`,
        );

        return throwError(() => error);
      }),
    );
  }
}

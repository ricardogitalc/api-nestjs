import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
  Injectable,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Injectable()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger('HTTP');

  private formatStack(stack: string): string {
    if (!stack) return '';
    // Pega apenas as 2 primeiras linhas do stack trace
    return stack
      .split('\n')
      .slice(0, 2)
      .map((line) => line.trim())
      .join(' → ');
  }

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const message =
      exception instanceof HttpException
        ? exception.message
        : 'Internal server error';

    // Log simplificado
    this.logger.error(
      `[${status}] ${request.method} ${request.url} - ${message}${
        exception instanceof Error
          ? ` → ${this.formatStack(exception.stack)}`
          : ''
      }`,
    );

    response.status(status).json({
      statusCode: status,
      message,
    });
  }
}

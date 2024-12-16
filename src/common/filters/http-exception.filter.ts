import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Request, Response } from 'express';
import type { ApiResponse } from '../interfaces/responses-interface';

interface ExceptionResponse {
  data?: {
    message: string;
  };
  message?: string;
}

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  catch(exception: any, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const exceptionResponse =
      exception instanceof HttpException
        ? (exception.getResponse() as ExceptionResponse)
        : null;

    const message =
      exception instanceof HttpException
        ? exceptionResponse?.data?.message ||
          exceptionResponse?.message ||
          exception.message
        : 'Erro interno do servidor';

    const formatTimestamp = () => {
      const now = new Date();
      const day = String(now.getDate()).padStart(2, '0');
      const month = String(now.getMonth() + 1).padStart(2, '0'); // Mês começa em 0
      const year = now.getFullYear();
      const hours = String(now.getHours()).padStart(2, '0');
      const minutes = String(now.getMinutes()).padStart(2, '0');
      const seconds = String(now.getSeconds()).padStart(2, '0');
      return `${day}/${month}/${year} ${hours}:${minutes}:${seconds}`;
    };

    const errorResponse: ApiResponse = {
      result: 'error',
      statusCode: status,
      data: { message },
      timestamp: formatTimestamp(),
      path: request.url,
    };

    response.status(status).json(errorResponse);
  }
}

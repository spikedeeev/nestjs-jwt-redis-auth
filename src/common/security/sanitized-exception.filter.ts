import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  Logger,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { sanitizeErrorMessage, sanitizeForLogs } from './sanitize-logs.util';

@Catch()
export class SanitizedExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(SanitizedExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const request = ctx.getRequest<Request>();
    const response = ctx.getResponse<Response>();

    const status =
      exception instanceof HttpException ? exception.getStatus() : 500;

    const sanitizedException = sanitizeForLogs(exception);
    const sanitizedRequest = sanitizeForLogs({
      method: request.method,
      url: request.url,
      headers: request.headers,
      query: request.query,
      params: request.params,
      body: request.body,
    });

    const message =
      exception instanceof Error
        ? sanitizeErrorMessage(exception.message)
        : sanitizeErrorMessage(String(exception));

    const stack =
      exception instanceof Error ? sanitizeErrorMessage(exception.stack) : undefined;

    this.logger.error(
      `HTTP ${request.method} ${request.url} failed: ${message}`,
      stack,
      SanitizedExceptionFilter.name,
    );
    this.logger.debug(
      `Sanitized request context: ${JSON.stringify(sanitizedRequest)}`,
      JSON.stringify(sanitizedException),
    );

    const errorResponse =
      exception instanceof HttpException
        ? sanitizeForLogs(exception.getResponse())
        : { message: 'Internal server error' };

    const responseBody =
      typeof errorResponse === 'string'
        ? {
            message: sanitizeErrorMessage(errorResponse),
            statusCode: status,
          }
        : {
            ...errorResponse,
            statusCode: status,
          };

    response.status(status).json(responseBody);
  }
}

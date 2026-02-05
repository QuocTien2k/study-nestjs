import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Response } from 'express';
import { ApiResponse } from '../bases/api-response';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();

    const status = exception.getStatus();
    const exceptionResponse = exception.getResponse() as any;

    const message =
      typeof exceptionResponse === 'string'
        ? exceptionResponse
        : (exceptionResponse.message ?? 'Error');

    const errors =
      typeof exceptionResponse === 'object'
        ? exceptionResponse.errors
        : undefined;

    response.status(status).json(
      new ApiResponse({
        status: false,
        code: status,
        message: Array.isArray(message) ? message.join(', ') : message,
        errors,
      }),
    );
  }
}

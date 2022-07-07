import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
} from '@nestjs/common';
import { Response } from 'express';

@Catch(HttpException)
export class GlobalHttpExceptionFilter
  implements ExceptionFilter<HttpException>
{
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const status = exception.getStatus();
    const exceptionObj = exception.getResponse().valueOf();

    response.status(status).json({
      statusCode: status,
      message: exception.message ? exception.message : 'Internal Server Error',
      errors: exceptionObj.hasOwnProperty('errors')
        ? exceptionObj['errors']
        : {},
    });
  }
}

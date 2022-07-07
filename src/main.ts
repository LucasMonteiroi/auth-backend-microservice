import { NestFactory } from '@nestjs/core';
import { SwaggerModule } from '@nestjs/swagger';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston/dist/winston.constants';
import { AppModule } from './app.module';
import { GlobalHttpExceptionFilter } from './core/filters/http-exception-filter';
import { createDocument } from './swagger/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.useLogger(app.get(WINSTON_MODULE_NEST_PROVIDER));
  app.useGlobalFilters(new GlobalHttpExceptionFilter());

  app.setGlobalPrefix('api/v1');
  SwaggerModule.setup('', app, createDocument(app));
  await app.listen(process.env.PORT || 3000);
}
bootstrap();

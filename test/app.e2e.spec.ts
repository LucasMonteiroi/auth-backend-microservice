import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';

import { HttpModule } from '@nestjs/axios';
import { AppModule } from '../src/app.module';
import { WinstonConfigService } from '../src/config';
import { WinstonModule, WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import { GlobalHttpExceptionFilter } from '../src/core/filters/http-exception-filter';

describe('App (e2e)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    jest.setTimeout(10000);
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        AppModule,
        HttpModule,
        WinstonModule.forRootAsync({
          useClass: WinstonConfigService,
        }),
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useLogger(app.get(WINSTON_MODULE_NEST_PROVIDER));
    app.useGlobalFilters(new GlobalHttpExceptionFilter());
    await app.init();
  });

  it('should be defined', async () => {
    expect(app).toBeDefined();
  });
});

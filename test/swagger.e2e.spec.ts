import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';

import { AppModule } from '../src/app.module';
import { SwaggerModule } from '@nestjs/swagger';
import { createDocument, SWAGGER_CONFIG } from '../src/swagger';

describe('Swagger (e2e)', () => {
  let app: INestApplication;
  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    app = moduleFixture.createNestApplication();
    SWAGGER_CONFIG.tags.push('Test');
    SwaggerModule.setup('', app, createDocument(app));
    await app.init();
  });

  it('/api (GET)', async () => {
    return request(app.getHttpServer()).get('/').expect(200);
  });
});

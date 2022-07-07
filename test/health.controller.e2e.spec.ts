import { TYPEORM_TEST } from '../src/environments/index';
import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { TypeOrmModule } from '@nestjs/typeorm';
import * as supertest from 'supertest';
import { getMetadataArgsStorage } from 'typeorm';
import { HealthModule } from '../src/health/health.module';

describe('Health', () => {
  let app: INestApplication;
  jest.setTimeout(20000);

  beforeAll(async () => {
    const module = await Test.createTestingModule({
      imports: [
        HealthModule,
        TypeOrmModule.forRoot({
          ...TYPEORM_TEST,
          type: 'postgres',
          schema: 'public',
          synchronize: true,
          entities: getMetadataArgsStorage().tables.map((tbl) => tbl.target),
          autoLoadEntities: true,
          logging: true,
        }),
      ],
    }).compile();

    app = module.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('GET /database', () => {
    it('should return an health check of database', async () => {
      const { body } = await supertest
        .agent(app.getHttpServer())
        .get('/health/database')
        .set('Accept', 'application/json')
        .expect('Content-Type', /json/)
        .expect(200);
      expect(body).toMatchObject({
        status: 'ok',
        info: {
          typeorm: {
            status: 'up',
          },
        },
        error: {},
        details: {
          typeorm: {
            status: 'up',
          },
        },
      });
    });
  });

  describe('GET /storage', () => {
    it('should return an health check of storage', async () => {
      const { body } = await supertest
        .agent(app.getHttpServer())
        .get('/health/storage')
        .set('Accept', 'application/json')
        .expect('Content-Type', /json/)
        .expect(200);
      expect(body).toMatchObject({
        status: 'ok',
        info: {
          'disk health': {
            status: 'up',
          },
        },
        error: {},
        details: {
          'disk health': {
            status: 'up',
          },
        },
      });
    });
  });

  describe('GET /memory', () => {
    it('should return an health check of storage', async () => {
      const { body } = await supertest
        .agent(app.getHttpServer())
        .get('/health/memory')
        .set('Accept', 'application/json')
        .expect('Content-Type', /json/)
        .expect(200);
      expect(body).toMatchObject({
        status: 'ok',
        info: {
          memory_heap: {
            status: 'up',
          },
          memory_rss: {
            status: 'up',
          },
        },
        error: {},
        details: {
          memory_heap: {
            status: 'up',
          },
          memory_rss: {
            status: 'up',
          },
        },
      });
    });

    it('should return an Service Unavailable health check of storage', async () => {
      return supertest
        .agent(app.getHttpServer())
        .get('/health/memory')
        .set('Accept', 'application/json')
        .expect('Content-Type', /json/)
        .expect(503);
    });
  });
});

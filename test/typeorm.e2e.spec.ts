import { Test } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';

import { TYPEORM } from '../src/environments';
import { TypeOrmModule } from '@nestjs/typeorm';
import { TasksModule } from '../src/modules/tasks/tasks.module';
import { getMetadataArgsStorage } from 'typeorm';

describe('Task', () => {
  let app: INestApplication;
  jest.setTimeout(20000);

  beforeAll(async () => {
    const module = await Test.createTestingModule({
      imports: [
        TasksModule,
        TypeOrmModule.forRoot({
          ...TYPEORM,
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

  it('ensure typeORM Database', async () => {
    expect(TYPEORM).toHaveProperty('database', 'backend_microservice');
  });
});

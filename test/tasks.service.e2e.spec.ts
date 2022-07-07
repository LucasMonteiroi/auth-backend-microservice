import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { TypeOrmModule } from '@nestjs/typeorm';
import * as supertest from 'supertest';
import { getMetadataArgsStorage, Repository } from 'typeorm';
import Task from '../src/modules/tasks/entities/task.entity';
import { TasksModule } from '../src/modules/tasks/tasks.module';
import { uuid } from 'uuidv4';
import { TYPEORM_TEST } from '../src/environments';

describe('Task', () => {
  let app: INestApplication;
  let repository: Repository<Task>;
  jest.setTimeout(20000);

  beforeAll(async () => {
    const module = await Test.createTestingModule({
      imports: [
        TasksModule,
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
    repository = module.get('TaskRepository');
    await app.init();
  });

  afterEach(async () => {
    await repository.query(`DELETE FROM ${Task.name}`);
  });

  afterAll(async () => {
    await app.close();
  });

  describe('GET /tasks', () => {
    it('should return an array of tasks', async () => {
      await repository.save([
        { description: 'test-name-0' },
        { description: 'test-name-1' },
      ]);
      const { body } = await supertest
        .agent(app.getHttpServer())
        .get('/tasks')
        .set('Accept', 'application/json')
        .expect('Content-Type', /json/)
        .expect(200);
      expect(body).toMatchObject([
        {
          description: 'test-name-0',
          done: false,
        },
        {
          description: 'test-name-1',
          done: false,
        },
      ]);
    });

    it('should return by id a created task', async () => {
      const { body: task } = await supertest
        .agent(app.getHttpServer())
        .post('/tasks')
        .set('Accept', 'application/json')
        .send({ description: 'test-before' })
        .expect('Content-Type', /json/)
        .expect(201);

      const { body: getTask } = await supertest
        .agent(app.getHttpServer())
        .get(`/tasks/${task.id}`)
        .set('Accept', 'application/json')
        .expect('Content-Type', /json/)
        .expect(200);

      expect(getTask).toHaveProperty('description', 'test-before');
    });
  });

  describe('POST /tasks', () => {
    it('should return a task', async () => {
      const { body } = await supertest
        .agent(app.getHttpServer())
        .post('/tasks')
        .set('Accept', 'application/json')
        .send({ description: 'test-name' })
        .expect('Content-Type', /json/)
        .expect(201);
      expect(body).toHaveProperty('description', 'test-name');
    });

    it('should create a task is the DB', async () => {
      await expect(repository.findAndCount()).resolves.toEqual([[], 0]);
      await supertest
        .agent(app.getHttpServer())
        .post('/tasks')
        .set('Accept', 'application/json')
        .send({ description: 'test-name' })
        .expect('Content-Type', /json/)
        .expect(201);
      await expect((await repository.find()).shift()).toHaveProperty(
        'description',
        'test-name',
      );
    });

    it('should handle a missing description', async () => {
      await supertest
        .agent(app.getHttpServer())
        .post('/tasks')
        .set('Accept', 'application/json')
        .send({ none: 'test-none' })
        .expect('Content-Type', /json/)
        .expect(400);
    });
  });

  describe('PUT /tasks', () => {
    it('should create and update a task', async () => {
      const { body: task } = await supertest
        .agent(app.getHttpServer())
        .post('/tasks')
        .set('Accept', 'application/json')
        .send({ description: 'test-before' })
        .expect('Content-Type', /json/)
        .expect(201);

      const { body: updatedTask } = await supertest
        .agent(app.getHttpServer())
        .patch(`/tasks/${task.id}`)
        .set('Accept', 'application/json')
        .send({ description: 'test-after' })
        .expect('Content-Type', /json/)
        .expect(200);

      expect(updatedTask).toHaveProperty('description', 'test-after');
    });

    it('should not update a insistent task', async () => {
      const { body: updatedTask } = await supertest
        .agent(app.getHttpServer())
        .patch(`/tasks/${uuid()}`)
        .set('Accept', 'application/json')
        .send({ description: 'test-after' })
        .expect('Content-Type', /json/)
        .expect(200);

      expect(updatedTask).toHaveProperty('updated', false);
    });
  });

  describe('DELETE /tasks', () => {
    it('should create and delete a task', async () => {
      const { body: task } = await supertest
        .agent(app.getHttpServer())
        .post('/tasks')
        .set('Accept', 'application/json')
        .send({ description: 'test-before' })
        .expect('Content-Type', /json/)
        .expect(201);

      const { body: deletedTask } = await supertest
        .agent(app.getHttpServer())
        .delete(`/tasks/${task.id}`)
        .set('Accept', 'application/json')
        .expect('Content-Type', /json/)
        .expect(200);

      expect(deletedTask).toHaveProperty('deleted', true);
    });

    it('should not delete a insistent task', async () => {
      const { body: updatedTask } = await supertest
        .agent(app.getHttpServer())
        .delete(`/tasks/${uuid()}`)
        .set('Accept', 'application/json')
        .expect('Content-Type', /json/)
        .expect(200);

      expect(updatedTask).toHaveProperty('deleted', false);
    });
  });
});

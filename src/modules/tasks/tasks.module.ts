/* eslint-disable @typescript-eslint/no-var-requires */
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { TasksController } from './controllers/tasks.controller';
import Task from './entities/task.entity';
import { TasksService } from './services/tasks.service';

@Module({
  imports: [TypeOrmModule.forFeature([Task])],
  providers: [TasksService],
  exports: [TasksService],
  controllers: [TasksController],
})
export class TasksModule {}

import { Logger, Module } from '@nestjs/common';
import { CoreModule } from './core/core.module';
import { TasksModule } from './modules/tasks/tasks.module';

@Module({
  imports: [CoreModule, TasksModule],
  providers: [Logger],
})
export class AppModule {}

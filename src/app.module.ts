import { Logger, Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { CoreModule } from './core/core.module';
import { TasksModule } from './modules/tasks/tasks.module';

@Module({
  imports: [CoreModule, TasksModule, AuthModule],
  providers: [Logger],
})
export class AppModule {}

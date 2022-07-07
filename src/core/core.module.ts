import { WinstonConfigService, TypeOrmService } from '../config';
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { WinstonModule } from 'nest-winston';
import { HealthModule } from '../health/health.module';

@Module({
  controllers: [],
  providers: [],
  imports: [
    WinstonModule.forRootAsync({
      useClass: WinstonConfigService,
    }),
    TypeOrmModule.forRootAsync({
      useClass: TypeOrmService,
    }),
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    HealthModule,
  ],
})
export class CoreModule {}

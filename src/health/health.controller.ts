import { Controller, Get } from '@nestjs/common';
import {
  DiskHealthIndicator,
  HealthCheck,
  HealthCheckService,
  MemoryHealthIndicator,
  TypeOrmHealthIndicator,
} from '@nestjs/terminus';
import { ApiOperation, ApiTags } from '@nestjs/swagger';

@ApiTags('health')
@Controller('health')
export class HealthController {
  constructor(
    private readonly health: HealthCheckService,
    private readonly typeOrmIndicator: TypeOrmHealthIndicator,
    private readonly diskHealthIndicator: DiskHealthIndicator,
    private readonly memoryHealthIndicator: MemoryHealthIndicator,
  ) {}

  @Get('/database')
  @HealthCheck()
  @ApiOperation({ summary: 'Database health check' })
  async checkDatabases() {
    return this.health.check([
      () => this.typeOrmIndicator.pingCheck('typeorm'),
    ]);
  }

  @Get('/storage')
  @HealthCheck()
  @ApiOperation({ summary: 'Storage health check' })
  async checkStorage() {
    return this.health.check([
      () =>
        this.diskHealthIndicator.checkStorage('disk health', {
          threshold: 250 * 1024 * 1024 * 1024,
          path: '/',
        }),
    ]);
  }

  @Get('/memory')
  @HealthCheck()
  @ApiOperation({ summary: 'Memory heap ans rss health check' })
  async checkMemory() {
    return this.health.check([
      async () =>
        this.memoryHealthIndicator.checkHeap('memory_heap', 200 * 1024 * 1024),
      async () =>
        this.memoryHealthIndicator.checkRSS('memory_rss', 3000 * 1024 * 1024),
    ]);
  }
}

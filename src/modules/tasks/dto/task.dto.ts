import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional } from 'class-validator';

export class TaskDto {
  @ApiProperty({ example: 'Task 1', description: 'Task description' })
  @IsNotEmpty()
  description: string;

  @ApiProperty({ example: true, description: 'Task done' })
  @IsOptional()
  done?: boolean;
}

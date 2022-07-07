import { ApiProperty } from '@nestjs/swagger';
import { randomUUID } from 'crypto';
import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
} from 'typeorm';

@Entity()
class Task {
  @PrimaryGeneratedColumn('uuid')
  @ApiProperty({ example: randomUUID(), description: 'Task id' })
  id?: string;

  @Column()
  @ApiProperty({ example: 'Task 1', description: 'Task description' })
  description: string;

  @Column({ nullable: true, default: false })
  @ApiProperty({ example: true, description: 'Task done' })
  done: boolean;

  @Column()
  @CreateDateColumn()
  @ApiProperty({
    example: new Date().toISOString(),
    description: 'Task created date',
  })
  createdAt?: Date;
}

export default Task;

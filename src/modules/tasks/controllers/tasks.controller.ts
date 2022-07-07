import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  UsePipes,
} from '@nestjs/common';
import { ApiBody, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { ValidationPipe } from '../../../core/pipes/validation.pipe';
import { TaskDto } from '../dto/task.dto';
import Task from '../entities/task.entity';
import { TasksService } from '../services/tasks.service';

@ApiTags('tasks')
@Controller('tasks')
@UsePipes(new ValidationPipe())
export class TasksController {
  constructor(private readonly taskService: TasksService) {}

  @Post()
  @ApiOperation({ summary: 'Create task' })
  @ApiResponse({
    status: 200,
    description: 'The created task',
    type: Task,
  })
  @ApiBody({ type: TaskDto })
  public async createTask(@Body() task: TaskDto) {
    return this.taskService.create({
      description: task.description,
      done: task.done,
    });
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get task by Id' })
  @ApiResponse({
    status: 200,
    description: 'The found task',
    type: Task,
  })
  public async getTaskbyId(@Param('id', ParseUUIDPipe) id: string) {
    return this.taskService.findById(id);
  }

  @Get()
  @ApiOperation({ summary: 'Get all tasks' })
  @ApiResponse({
    status: 200,
    description: 'All tasks',
    type: Task,
    isArray: true,
  })
  public async getTask() {
    return this.taskService.find();
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update task' })
  @ApiResponse({
    status: 200,
    description: 'Update result',
    type: Boolean,
  })
  public async updateTask(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: TaskDto,
  ) {
    return this.taskService.update({
      id,
      description: dto.description,
      done: dto.done,
    });
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete task' })
  @ApiResponse({
    status: 200,
    description: 'Delete result',
    type: Boolean,
  })
  public async deleteTask(@Param('id', ParseUUIDPipe) id: string) {
    return this.taskService.delete(id);
  }
}

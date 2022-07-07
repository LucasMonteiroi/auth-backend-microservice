import { Test, TestingModule } from '@nestjs/testing';
import {
  BadRequestException,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { GlobalHttpExceptionFilter } from '../src/core/filters/http-exception-filter';
import { ValidationPipe } from '../src/core/pipes/validation.pipe';

const mockAppLoggerService = {
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
};
const mockJson = jest.fn();
const mockStatus = jest.fn().mockImplementation(() => ({
  json: mockJson,
}));
const mockGetResponse = jest.fn().mockImplementation(() => ({
  status: mockStatus,
}));
const mockHttpArgumentsHost = jest.fn().mockImplementation(() => ({
  getResponse: mockGetResponse,
  getRequest: jest.fn(),
}));

const mockArgumentsHost = {
  switchToHttp: mockHttpArgumentsHost,
  getArgByIndex: jest.fn(),
  getArgs: jest.fn(),
  getType: jest.fn(),
  switchToRpc: jest.fn(),
  switchToWs: jest.fn(),
};

describe('Core Module', () => {
  let service: GlobalHttpExceptionFilter;
  let pipe: ValidationPipe;

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        GlobalHttpExceptionFilter,
        ValidationPipe,
        {
          provide: Logger,
          useValue: mockAppLoggerService,
        },
      ],
    }).compile();
    service = module.get<GlobalHttpExceptionFilter>(GlobalHttpExceptionFilter);
    pipe = module.get<ValidationPipe>(ValidationPipe);
  });

  describe('All exception filter tests', () => {
    it('should be defined', () => {
      expect(service).toBeDefined();
    });

    it('Http exception', () => {
      service.catch(
        new HttpException(
          { message: 'Sample Exception' },
          HttpStatus.BAD_REQUEST,
        ),
        mockArgumentsHost,
      );
      expect(mockHttpArgumentsHost).toBeCalledTimes(1);
      expect(mockHttpArgumentsHost).toBeCalledWith();
      expect(mockGetResponse).toBeCalledTimes(1);
      expect(mockGetResponse).toBeCalledWith();
      expect(mockStatus).toBeCalledTimes(1);
      expect(mockStatus).toBeCalledWith(HttpStatus.BAD_REQUEST);
      expect(mockJson).toBeCalledTimes(1);
    });
  });

  describe('All pipes tests', () => {
    it('should be defined', () => {
      expect(pipe).toBeDefined();
    });

    it('Validation Pipe', async () => {
      const response = await pipe.transform(null, { type: 'body' });
      expect(response).toBeInstanceOf(BadRequestException);
    });
  });
});

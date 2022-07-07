import { Injectable } from '@nestjs/common';
import {
  utilities as nestWinstonModuleUtilities,
  WinstonModuleOptionsFactory,
} from 'nest-winston';
import * as winston from 'winston';

@Injectable()
export class WinstonConfigService implements WinstonModuleOptionsFactory {
  setupFormat() {
    return winston.format.combine(
      winston.format.printf((transformableInfo) => {
        return `[${new Date().toLocaleString()}]: [${transformableInfo.level.toUpperCase()}] [Winston] [${
          transformableInfo.context
        }] ${transformableInfo.message} ${
          transformableInfo.stack ? transformableInfo.stack : ''
        }`;
      }),
    );
  }

  setupConsoleFormat() {
    return winston.format.combine(
      winston.format.timestamp(),
      winston.format.colorize({
        all: true,
        colors: {
          error: 'red',
          info: 'cyan',
          verbose: 'magenta',
          warn: 'green',
        },
      }),
      nestWinstonModuleUtilities.format.nestLike('Winston', {
        prettyPrint: true,
      }),
    );
  }

  filePrefix() {
    return [
      new Date().getFullYear().toString(),
      new Date().getMonth().toString().padStart(2, '0'),
      new Date().getDate().toString().padStart(2, '0'),
    ].join('-');
  }

  createWinstonModuleOptions():
    | winston.LoggerOptions
    | Promise<winston.LoggerOptions> {
    return {
      transports: [
        new winston.transports.File({
          filename: `${process.cwd()}/logs/error/${this.filePrefix()}-error.log`,
          level: 'error',
          format: this.setupFormat(),
          handleExceptions: true,
        }),
        new winston.transports.File({
          filename: `${process.cwd()}/logs/info/${this.filePrefix()}-info.log`,
          level: 'info',
          format: this.setupFormat(),
        }),
        new winston.transports.File({
          filename: `${process.cwd()}/logs/${this.filePrefix()}-combined.log`,
          format: this.setupFormat(),
        }),
        new winston.transports.Console({
          format: this.setupConsoleFormat(),
        }),
      ],
    };
  }
}

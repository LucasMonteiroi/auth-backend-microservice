import { TYPEORM } from '../../environments';
import { Injectable } from '@nestjs/common';
import { TypeOrmOptionsFactory, TypeOrmModuleOptions } from '@nestjs/typeorm';
import { getMetadataArgsStorage } from 'typeorm';

@Injectable()
export class TypeOrmService implements TypeOrmOptionsFactory {
  async createTypeOrmOptions(): Promise<TypeOrmModuleOptions> {
    return {
      ...TYPEORM,
      type: 'postgres',
      schema: 'public',
      synchronize: true,
      entities: getMetadataArgsStorage().tables.map((tbl) => tbl.target),
      autoLoadEntities: true,
      logging: true,
    };
  }
}

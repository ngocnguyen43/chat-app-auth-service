import { id, inject, injectable } from 'inversify';

import { Prisma, PrismaClient } from '@prisma/client';
import { DefaultArgs } from '@prisma/client/runtime';

import { TYPES } from '../types';
import { AuthCreateDto, AuthnPasswordDto } from '@v1';
import { Options, decode, encode } from '../../../utils';

export interface IAuthRepository {
  AddPassword(dto: AuthnPasswordDto): Promise<void>;
  CreateOne(dto: AuthCreateDto): Promise<void>;
  PasswordLogin(dto: { id: string; password: string }): Promise<any>;
  LoginOptions(id: string): Promise<any>;
}
@injectable()
export class AuthRepository implements IAuthRepository {
  constructor(
    @inject(TYPES.Prisma)
    private readonly _db: PrismaClient<
      Prisma.PrismaClientOptions,
      never,
      Prisma.RejectOnNotFound | Prisma.RejectPerOperation,
      DefaultArgs
    >,
  ) {}
  async LoginOptions(id: string): Promise<any> {
    const options = await this._db.authnOptions.findMany({
      where: {
        userId: id,
        NOT: {
          option: 'password',
        },
      },
    });
    return Options(options);
  }
  async PasswordLogin(dto: { id: string; password: string }): Promise<any> {
    try {
      const auth = await this._db.authnOptions.findFirst({
        where: {
          option: 'password',
          userId: dto.id,
        },
      });
      if (!auth) {
        return { message: 'wrong pssword' };
      }
      const { value } = auth.key as Prisma.JsonObject;
      const isSimilar = await decode(dto.password, value as string);
      if (isSimilar) {
        return { ok: 'ok' };
      }
      return { message: 'wrong password' };
    } catch (error) {
      console.log(error);
      return { err: 'err' };
    }
  }

  async CreateOne(dto: AuthCreateDto): Promise<any> {
    const execute: string | any[] = [];
    execute.push(
      this._db.user.create({
        data: {
          id: dto.id,
        },
      }),
    );
    await this._db.$transaction(execute);
  }
  async AddPassword(dto: AuthnPasswordDto) {
    const execute: string | any[] = [];
    const json = {
      value: await encode(dto.pasword),
    } as Prisma.JsonObject;
    execute.push(
      this._db.authnOptions.create({
        data: {
          option: 'password',
          userId: dto.id,
          key: json,
        },
      }),
    );
    await this._db.$transaction(execute);
  }
}

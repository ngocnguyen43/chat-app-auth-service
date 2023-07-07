import { inject, injectable } from 'inversify';

import { Prisma, PrismaClient } from '@prisma/client';
import { DefaultArgs } from '@prisma/client/runtime';

import { TYPES } from '../types';

export interface IAuthRepository {
  AddPassword: () => Promise<any>;
}
@injectable()
export class AuthRepository implements IAuthRepository {
  constructor(
    @inject(TYPES.Prisma)
    private readonly db: PrismaClient<
      Prisma.PrismaClientOptions,
      never,
      Prisma.RejectOnNotFound | Prisma.RejectPerOperation,
      DefaultArgs
    >,
  ) {}
  public AddPassword = async () => {
    const users = await this.db.user.findMany();
    return users;
  };
}

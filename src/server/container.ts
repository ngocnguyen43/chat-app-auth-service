import { Container, ContainerModule } from 'inversify';

import { Prisma, PrismaClient } from '@prisma/client';
import { DefaultArgs } from '@prisma/client/runtime';

import { prisma } from '../api/v1/config';
import { AuthRepository, AuthService, IAuhtService, IAuthRepository, TYPES } from './auth/v1';

const thirdPartyDependencies = new ContainerModule((bind) => {
  bind<
    PrismaClient<Prisma.PrismaClientOptions, never, Prisma.RejectOnNotFound | Prisma.RejectPerOperation, DefaultArgs>
  >(TYPES.Prisma).toConstantValue(prisma);
  // ..
});

const applicationDependencies = new ContainerModule((bind) => {
  bind<IAuthRepository>(TYPES.AuthRepository).to(AuthRepository);
  bind<IAuhtService>(TYPES.AuthService).to(AuthService);
  // ..
});
export const container = new Container({
  defaultScope: 'Singleton',
});
container.load(thirdPartyDependencies, applicationDependencies);

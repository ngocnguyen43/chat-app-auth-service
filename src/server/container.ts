import { Container, ContainerModule } from 'inversify';

import { Prisma, PrismaClient } from '@prisma/client';
import { DefaultArgs } from '@prisma/client/runtime';

import { AuthRepository, AuthService, IAuhtService, IAuthRepository, TYPES } from './auth/v1';
import { RequestValidator } from './auth/v1/middleware';
import { prisma } from './config';
import { ITokenRepository, TokenRepository } from './auth/v1/repository/token.repository';

const thirdPartyDependencies = new ContainerModule((bind) => {
  bind<
    PrismaClient<Prisma.PrismaClientOptions, never, Prisma.RejectOnNotFound | Prisma.RejectPerOperation, DefaultArgs>
  >(TYPES.Prisma).toConstantValue(prisma);
  // ..
});

const applicationDependencies = new ContainerModule((bind) => {
  bind<IAuthRepository>(TYPES.AuthRepository).to(AuthRepository);
  bind<IAuhtService>(TYPES.AuthService).to(AuthService);
  bind<ITokenRepository>(TYPES.TokenRepository).to(TokenRepository);
  bind<RequestValidator>(RequestValidator).toSelf();
  // ..
});
export const container = new Container({
  defaultScope: 'Singleton',
});
container.load(thirdPartyDependencies, applicationDependencies);

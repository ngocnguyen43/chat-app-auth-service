import { Container, ContainerModule } from 'inversify';

import { Prisma, PrismaClient } from '@prisma/client';
import { DefaultArgs } from '@prisma/client/runtime';

import { prisma } from './config';
import { IMessageExecute, MessageExecute } from './message-broker/MessageExecute';
import { TYPES } from './auth';
import {
  AuthRepository,
  AuthService,
  IAuhtService,
  IAuthRepository,
  ITokenRepository,
  TokenRepository,
} from './auth/v1';
import { RequestValidator } from './auth/v1/middleware';

const thirdPartyDependencies = new ContainerModule((bind) => {
  bind<
    PrismaClient<Prisma.PrismaClientOptions, never, Prisma.RejectOnNotFound | Prisma.RejectPerOperation, DefaultArgs>
  >(TYPES.Prisma).toConstantValue(prisma);
  // ..
});

const applicationDependencies = new ContainerModule((bind) => {
  bind<IAuhtService>(TYPES.AuthService).to(AuthService);
  bind<IMessageExecute>(TYPES.MessageExecute).to(MessageExecute);
  bind<IAuthRepository>(TYPES.AuthRepository).to(AuthRepository);
  bind<ITokenRepository>(TYPES.TokenRepository).to(TokenRepository);
  bind<RequestValidator>(RequestValidator).toSelf();
  // ..
});

export const container = new Container({
  defaultScope: 'Singleton',
});
container.load(thirdPartyDependencies, applicationDependencies);
// const execute = container.resolve(MessageExecute);

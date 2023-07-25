import { Container, ContainerModule, inject, injectable } from 'inversify';

import { Prisma, PrismaClient } from '@prisma/client';
import { DefaultArgs } from '@prisma/client/runtime';

import { TYPES } from './auth';
import { AuthRepository, AuthService, IAuhtService, IAuthRepository } from './auth/v1';
import { RequestValidator } from './auth/v1/middleware';
import { prisma } from './config';
import { ITokenRepository, TokenRepository } from './auth/v1/repository/token.repository';
import { IMessageExecute, MessageExecute } from './message-broker/Messagehandler';

const thirdPartyDependencies = new ContainerModule((bind) => {
  bind<
    PrismaClient<Prisma.PrismaClientOptions, never, Prisma.RejectOnNotFound | Prisma.RejectPerOperation, DefaultArgs>
  >(TYPES.Prisma).toConstantValue(prisma);
  // ..
});

const applicationDependencies = new ContainerModule((bind) => {
  bind<IAuhtService>(TYPES.AuthService).to(AuthService).inTransientScope();
  bind<IAuthRepository>(TYPES.AuthRepository).to(AuthRepository).inTransientScope();
  bind<ITokenRepository>(TYPES.TokenRepository).to(TokenRepository);
  bind<IMessageExecute>(TYPES.MessageExecute).to(MessageExecute);
  bind<RequestValidator>(RequestValidator).toSelf();
  // ..
});

export const container = new Container({
  defaultScope: 'Singleton',
});
container.load(thirdPartyDependencies, applicationDependencies);

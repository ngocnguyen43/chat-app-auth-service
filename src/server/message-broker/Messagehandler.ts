import { inject, injectable } from 'inversify';

import { IAuhtService, TYPES } from '../auth';
import { container } from '../container';
import RabbitMQClient from './RabbitMQClient';
import { IMessageExecute } from './MessageExecute';

export class MessageHandler {
  static async handle(data: any, correlationId?: string, replyTo?: string) {
    const { type, payload } = data;
    if (correlationId && replyTo) {
      const response = await container.get<IMessageExecute>(TYPES.MessageExecute).execute(type, payload);
      await RabbitMQClient.serverProduce(response, correlationId, replyTo);
    } else {
      await container.get<IMessageExecute>(TYPES.MessageExecute).noResponseExecute(type, payload);
    }
  }
}

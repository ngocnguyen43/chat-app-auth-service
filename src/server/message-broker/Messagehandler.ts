import { inject, injectable } from 'inversify';
import { IAuhtService, TYPES } from '../auth';
import { container } from '../container';
import RabbitMQClient from './RabbitMQClient';

export interface IMessageExecute {
  execute(name: string, payload: any): Promise<unknown>;
  noResponseExecute(name: string, payload: any): Promise<void>;
}
@injectable()
export class MessageExecute implements IMessageExecute {
  constructor(@inject(TYPES.AuthService) private readonly _service: IAuhtService) {}
  execute(name: string, payload: any): Promise<unknown> {
    throw new Error('Method not implemented.');
  }
  noResponseExecute(name: string, payload: any): Promise<void> {
    throw new Error('Method not implemented.');
  }
}

export class MessageHandler {
  static async handle(data: any, correlationId: string, replyTo: string) {
    const { type, payload } = data;

    const response = container.get<IMessageExecute>(MessageExecute).execute(type, payload);
    console.log(data);
    await RabbitMQClient.serverProduce({}, correlationId, replyTo);
  }
}

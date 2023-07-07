import RabbitMQClient from './RabbitMQClient';

export class MessageHandler {
  static async handle(data: any, correlationId: string, replyTo: string) {
    let response = { ok: data['id'] };
    console.log(data);
    await RabbitMQClient.serverProduce(response, correlationId, replyTo);
  }
}

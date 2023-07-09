import { Channel, Message } from 'amqplib';
import EventEmitter from 'events';

import { MessageHandler } from './Messagehandler';

export class Consumer {
  constructor(private chanel: Channel, private replyQueue?: string, private eventEmitter?: EventEmitter) {}
  async clientComsumeMessage() {
    this.chanel.consume(
      this.replyQueue,
      (message: Message) => {
        console.log('reply....', message.content.toString());
        this.eventEmitter.emit(message.properties.correlationId.toString(), message);
      },
      { noAck: true },
    );
  }
  serverComsumeMessage = async () => {
    this.chanel.consume(
      this.replyQueue,
      (message: Message) => {
        (async () => {
          const { correlationId, replyTo } = message.properties;
          console.log(message.content.toString());
          if (!correlationId || !replyTo) {
            console.log('Missing some properties...');
          }
          await MessageHandler.handle(JSON.parse(message.content.toString()), correlationId, replyTo);
        })();
      },
      {
        noAck: true,
      },
    );
  };
}

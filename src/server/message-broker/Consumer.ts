import { Channel, Message } from 'amqplib';
import EventEmitter from 'events';

export class Consumer {
  constructor(private chanel: Channel, private replyQueue: string, private eventEmitter: EventEmitter) {}
  async comsumeMessage() {
    this.chanel.consume(
      this.replyQueue,
      (message: Message) => {
        console.log('reply....', message.content.toString());
        this.eventEmitter.emit(message.properties.correlationId.toString(), message);
      },
      { noAck: true },
    );
  }
}

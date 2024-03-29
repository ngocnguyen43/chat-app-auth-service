import { Channel } from 'amqplib';
import { randomUUID } from 'crypto';
import EventEmitter from 'events';

export class Producer {
  constructor(private chanel: Channel, private replyQueue?: string, private eventEmitter?: EventEmitter) { }
  async clientProduceMessages(target: string, message: any) {
    const uuid = randomUUID();
    console.log('correId::::::', uuid);
    this.chanel.sendToQueue(target, Buffer.from(JSON.stringify(message)), {
      replyTo: this.replyQueue,
      correlationId: uuid,
      expiration: 10,
    });
    return new Promise((resolve, reject) => {
      const timeoutDuration = 5000; // Set your desired timeout duration in milliseconds
      const timeoutId = setTimeout(() => {
        reject(new Error('Timeout: No message found in event within the specified time.'));
      }, timeoutDuration);
      this.eventEmitter.once(uuid, async (data) => {
        clearTimeout(timeoutId);
        const reply = JSON.parse(data.content.toString());
        resolve(reply);
      });
    });
  }
  async serverProduceMessage(message: any, correlationId: string, replyToQueue: string) {
    this.chanel.sendToQueue(replyToQueue, Buffer.from(JSON.stringify(message)), {
      correlationId: correlationId,
    });
  }
  noReplyProduce(message: any, replyToQueue: string) {
    this.chanel.sendToQueue(replyToQueue, Buffer.from(JSON.stringify(message)));
  }
}

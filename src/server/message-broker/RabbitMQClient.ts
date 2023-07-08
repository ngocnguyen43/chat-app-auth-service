import { Channel, connect, Connection } from 'amqplib';
import EventEmitter from 'events';

import { config } from '../config';
import { Consumer } from './Consumer';
import { Producer } from './Producer';
import { logger } from '../common/logger';
export interface IRabbitMQClient {
  initialize: (name: string) => Promise<void>;
}
const EXCHANGE_NAME = 'm-broker';
class RabbitMQClient implements IRabbitMQClient {
  private constructor() {}

  private static instance: RabbitMQClient;
  private isInitialized = false;

  private connection: Connection;
  private clientProducer: Producer;
  private clientConsumer: Consumer;
  private clientProducerChannel: Channel;
  private clientConsumerChanel: Channel;

  private serverProducer: Producer;
  private serverConsumer: Consumer;
  private serverProducerChannel: Channel;
  private serverConsumerChanel: Channel;

  private receiveChanel: Channel;
  private emitChanel: Channel;

  private eventEmitter: EventEmitter;

  public static getInstance() {
    if (!this.instance) {
      this.instance = new RabbitMQClient();
    }
    return this.instance;
  }

  initialize = async (name: string) => {
    if (this.isInitialized) {
      return;
    }
    try {
      this.connection = await connect(config['MESSAGE_BROKER_URL']);
      logger.info('connect to rabbitMQ  successfully');
      if (this.connection) {
        this.serverProducerChannel = await this.connection.createChannel();
        this.serverConsumerChanel = await this.connection.createChannel();
        const { queue: replyQueue } = await this.serverConsumerChanel.assertQueue(name, { exclusive: true });
        this.serverProducer = new Producer(this.serverProducerChannel, replyQueue);
        this.serverConsumer = new Consumer(this.serverConsumerChanel, replyQueue);
        this.serverConsumer.serverComsumeMessage();

        this.clientProducerChannel = await this.connection.createChannel();
        this.clientConsumerChanel = await this.connection.createChannel();
        const { queue: clientReplyQueue } = await this.clientConsumerChanel.assertQueue('', { exclusive: true });
        this.eventEmitter = new EventEmitter();
        this.clientProducer = new Producer(this.clientProducerChannel, clientReplyQueue, this.eventEmitter);
        this.clientConsumer = new Consumer(this.clientConsumerChanel, clientReplyQueue, this.eventEmitter);
        this.clientConsumer.clientComsumeMessage();

        this.receiveChanel = await this.connection.createChannel();
        this.emitChanel = await this.connection.createChannel();

        this.receiveChanel.assertExchange(EXCHANGE_NAME, 'direct');
        this.emitChanel.assertExchange(EXCHANGE_NAME, 'direct');

        this.isInitialized = true;
      }
    } catch (error) {
      console.log(error);
    }
  };
  async clientProduce(target: string, data: any) {
    if (!this.connection) {
      logger.error('rabbitMQ connection error');
      return;
    }
    return await this.clientProducer.clientProduceMessages(target, data);
  }
  serverProduce = async (data: any, correlationId?: string, replyToQueue?: string) => {
    if (!this.connection) {
      logger.error('cannot produce message because no rabbitMQ connection');
      return;
    }
    return await this.serverProducer.serverProduceMessage(data, correlationId, replyToQueue);
  };
  async receiveMessage() {
    const q = await this.receiveChanel.assertQueue('auth-service-queue');
    await this.receiveChanel.bindQueue(q.queue, EXCHANGE_NAME, '');

    this.receiveChanel.consume(
      q.queue,
      (msg) => {
        console.log(` [x] ${msg.fields.routingKey}: '${msg.content.toString()}'`);
      },
      { noAck: true },
    );
  }
}
export default RabbitMQClient.getInstance();

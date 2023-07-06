import { Channel, connect, Connection } from 'amqplib';
import EventEmitter from 'events';

import { config } from '../config';
import { Consumer } from './Consumer';
import { Producer } from './Producer';
import { logger } from '../common/logger';
export interface IRabbitMQClient {
  initialize: (name: string) => Promise<void>;
}
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
        this.serverConsumer.clientComsumeMessage();

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
    return await this.clientProduce(target, data);
  }
  serverProduce = async (data: any, correlationId?: string, replyToQueue?: string) => {
    if (!this.connection) {
      logger.error('cannot produce message because no rabbitMQ connection');
      return;
    }
    return await this.serverProducer.serverProduceMessage(data, correlationId, replyToQueue);
  };
  toClient = async () => {
    this.clientProducerChannel = await this.connection.createChannel();
    this.clientConsumerChanel = await this.connection.createChannel();
    const { queue: replyQueue } = await this.clientConsumerChanel.assertQueue('', { exclusive: true });
    this.eventEmitter = new EventEmitter();
    this.clientProducer = new Producer(this.clientProducerChannel, replyQueue, this.eventEmitter);
    this.clientConsumer = new Consumer(this.clientConsumerChanel, replyQueue, this.eventEmitter);
    this.clientConsumer.clientComsumeMessage();
    return this;
  };
}
export default RabbitMQClient.getInstance();

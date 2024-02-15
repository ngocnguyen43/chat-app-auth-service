import { Channel, connect, Connection } from 'amqplib';
import EventEmitter from 'stream';

import { logger } from '../common/logging';
import { config } from '../config';
import { Consumer } from './Consumer';
import { Producer } from './Producer';

export interface IRabbitMQClient {
  initialize: (name: string) => Promise<void>;
}
const EXCHANGE_NAME = 'm-broker';
class RabbitMQClient implements IRabbitMQClient {
  private constructor() { }

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
        const { queue: replyQueue } = await this.serverConsumerChanel.assertQueue(name, { autoDelete: true });
        this.serverProducer = new Producer(this.serverProducerChannel, replyQueue);
        this.serverConsumer = new Consumer(this.serverConsumerChanel, replyQueue);
        this.serverConsumer.serverComsumeMessage();

        this.clientProducerChannel = await this.connection.createChannel();
        this.clientConsumerChanel = await this.connection.createChannel();
        const { queue: clientReplyQueue } = await this.clientConsumerChanel.assertQueue("", { exclusive: true });
        this.eventEmitter = new EventEmitter();
        this.clientProducer = new Producer(this.clientProducerChannel, clientReplyQueue, this.eventEmitter);
        this.clientConsumer = new Consumer(this.clientConsumerChanel, clientReplyQueue, this.eventEmitter);
        this.clientConsumer.clientComsumeMessage();

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
  messageProduce(target: string, data: any) {
    if (!this.connection) {
      logger.error('rabbitMQ connection error');
      return;
    }
    try {
      return this.serverProducer.noReplyProduce(data, target);
    } catch (error) {
      console.log(error);
    }
  }
}
export default RabbitMQClient.getInstance();

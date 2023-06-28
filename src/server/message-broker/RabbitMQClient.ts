import { Channel, connect, Connection } from 'amqplib';
import EventEmitter from 'events';

import { config } from '../config';
import { Consumer } from './Consumer';
import { Producer } from './Producer';
import { retryConnection } from '../utils';
export interface IRabbitMQClient {
  initialize: () => Promise<void>;
}
class RabbitMQClient implements IRabbitMQClient {
  private constructor() {}

  private static instance: RabbitMQClient;
  private isInitialized = false;

  private producer: Producer;
  private consumer: Consumer;
  private connection: Connection;
  private producerChannel: Channel;
  private consumerChannel: Channel;

  private eventEmitter: EventEmitter;

  public static getInstance() {
    if (!this.instance) {
      this.instance = new RabbitMQClient();
    }
    return this.instance;
  }

  initialize = async () => {
    if (this.isInitialized) {
      return;
    }
    try {
      this.connection = await retryConnection<Connection>(3, connect(config['MESSAGE_BROKER_URL']), 'rabbitMQ', 2);
      if (this.connection) {
        this.producerChannel = await this.connection.createChannel();
        this.consumerChannel = await this.connection.createChannel();
        const { queue: replyQueue } = await this.consumerChannel.assertQueue('', { exclusive: true });
        this.eventEmitter = new EventEmitter();
        this.producer = new Producer(this.producerChannel, replyQueue, this.eventEmitter);
        this.consumer = new Consumer(this.consumerChannel, replyQueue, this.eventEmitter);
        this.consumer.comsumeMessage();

        this.isInitialized = true;
      }
    } catch (error) {
      console.log(error);
    }
  };
  async produce(data: any) {
    if (!this.connection) {
      await this.initialize();
    }
    return await this.producer.produceMessages(data);
  }
}
export default RabbitMQClient.getInstance();

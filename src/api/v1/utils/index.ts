import amqplib from 'amqplib';

import { AuthnOptions, config } from '../config';

export { ErrorHandler } from './errorHandler';
export * from './responses';
export { encode } from './encode';
export { decode } from './decode';
export const Options = (arr: AuthnOptions[]) => {
  let obj = {
    password: true,
  };
  arr.forEach((item) => {
    obj[item.option] = true;
  });
  return obj;
};
export const createChanel = async () => {
  try {
    const connection = await amqplib.connect(config['MESSAGE_BROKER_URL']);
    const chanel = await connection.createChannel();

    await chanel.assertExchange(config['EXCHANGE_NAME'], 'direct', { durable: false });
    return chanel;
  } catch (error) {
    console.log(error);
  }
};
export const publishMessage = (chanel: amqplib.Channel, binding_key: string, message) => {
  try {
    chanel.publish(config['EXCHANGE_NAME'], binding_key, Buffer.from(message));
  } catch (error) {
    console.log(error);
  }
};
export const subscribeMessage = async (chanel: amqplib.Channel, binding_key: string, service) => {
  const appQueue = await chanel.assertQueue(config['QUEUE_NAME']);
  chanel.bindQueue(appQueue.queue, config['EXCHANGE_NAME'], binding_key);
  chanel.consume(appQueue.queue, (data) => {
    console.log(data.content.toString());
    chanel.ack(data);
  });
};

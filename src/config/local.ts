import * as dotenv from "dotenv"
dotenv.config()
export default {
  port: 6001,
  redis_port: process.env.REDIS_PORT_DEV || 1051,
  redis_host: process.env.REDIS_HOST || '127.0.0.1',
  MESSAGE_BROKER_URL: process.env.MESSAGE_BROKER_URL_DEV || 'amqp://127.0.0.1:5672',
  CONSUL_URL: process.env.CONSUL_HOST_DEV || '127.0.0.1',
  HOST_PORT: process.env.HOST_PORT || 6001
};

export default {
  port: 4343,
  redis_port: process.env.REDIS_PORT_TEST || 1051,
  redis_host: process.env.REDIS_HOST || '',
  MESSAGE_BROKER_URL: process.env.MESSAGE_BROKER_URL_DEV || '',
  CONSUL_URL: process.env.CONSUL_URL_DEV || '',
  ORIGIN: process.env.ORIGIN_URL || '',
};

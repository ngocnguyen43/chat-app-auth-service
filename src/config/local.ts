export default {
  port: 6001,
  redis_port: process.env.REDIS_PORT_DEV || 1051,
  redis_host: process.env.REDIS_HOST || '',
  MESSAGE_BROKER_URL: process.env.MESSAGE_BROKER_URL_DEV || '',
};

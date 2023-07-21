export default {
  port: 4000,
  redis_port: process.env.REDIS_PORT_PROD || 1051,
  redis_host: process.env.REDIS_HOST || '',
  MESSAGE_BROKER_URL: process.env.MESSAGE_BROKER_URL_DEV || '',
};

export default {
  port: 4343,
  REDIS_PORT: process.env.REDIS_PORT_DEV || 1051,
  REDIS_HOST: process.env.REDIS_HOST || '127.0.0.1',
  MESSAGE_BROKER_URL: process.env.MESSAGE_BROKER_URL_DEV || '',
  CONSUL_URL: process.env.CONSUL_URL_DEV || '',
  ORIGIN: process.env.ORIGIN_URL || '',
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || "",
  ORIGIN_API: process.env.ORIGIN_API || '',

};

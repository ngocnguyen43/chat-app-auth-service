import * as dotenv from "dotenv"
dotenv.config()
export default {
  port: 4000,
  redis_port: process.env.REDIS_PORT_PROD || 1051,
  redis_host: process.env.REDIS_HOST || '',
  MESSAGE_BROKER_URL: process.env.MESSAGE_BROKER_URL_DEV || '',
  CONSUL_URL: process.env.CONSUL_HOST_PROD || '',
  ORIGIN: process.env.ORIGIN_URL || '',
  COOKIES_DOMAIN: process.env.COOKIES_DOMAIN || "",
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || "",
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET || "",
  GITHUB_CLIENT_ID: process.env.GITHUB_CLIENT_ID || "",
  GITHUB_CLIENT_SECRET: process.env.GITHUB_CLIENT_SECRET || "",
  FACEBOOK_APP_ID: process.env.FACEBOOK_APP_ID || "",
  FACEBOOK_APP_SECRET: process.env.FACEBOOK_APP_SECRET || "",
  ORIGIN_API: process.env.ORIGIN_API || '',

};

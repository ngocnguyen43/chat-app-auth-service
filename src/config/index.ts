import * as dotenv from 'dotenv';
import merge from 'lodash.merge';
dotenv.config();

// make sure NODE_ENV is set
process.env.NODE_ENV = process.env.NODE_ENV || 'development';

const stage = process.env.STAGE || 'dev';
let envConfig;

// dynamically require each config depending on the stage we're in
if (stage == 'production') {
  envConfig = require('./production').default;
} else if (stage === 'test') {
  envConfig = require('./test').default;
} else {
  envConfig = require('./local').default;
}
export const config: {
  state: string;
  port: number;
  secrets: { jwt: string; dbUrl: string };
  logging: boolean;
} = merge(
  {
    stage,
    port: process.env.PORT,
    secrets: {
      jwt: process.env.JWT_SECRET,
      dbUrl: process.env.DATABASE_URL,
    },
    logging: false,
    EXCHANGE_NAME: 'CHAT_APP',
    USER_BINDDING_KEY: 'USER_SERVICE',
    SOCKET_BINDDING_KEY: 'SOCKET_SERVICE',
    QUEUE_NAME: 'AUTH_QUEUE',
  },
  envConfig,
);

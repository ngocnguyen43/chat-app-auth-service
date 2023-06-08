import merge from 'lodash.merge';

// make sure NODE_ENV is set
process.env.NODE_ENV = process.env.NODE_ENV || 'development';

const stage = process.env.STAGE || 'local';
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
  },
  envConfig,
);

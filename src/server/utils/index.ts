import { connect, Connection } from 'amqplib';
import bcrypt from 'bcrypt';
import { config } from '../config';
import crypto from "crypto"
import { promisify } from 'util';
import * as base32 from 'hi-base32';

export async function sleep(ms: number) {
  return new Promise<void>((resolve) => {
    setTimeout(() => {
      resolve();
    }, ms * 1000);
  });
}
// function connect<T>(fn: Promise<T>) {
//   return new Promise<T>((resolve, reject) => {
//     // const poolPromise = new sql.ConnectionPool("config.db");
//     const poolPromise = fn;
//     poolPromise
//       .then((pool) => {
//         console.log('connected');
//         resolve(pool);
//       })
//       .catch((err) => {
//         console.error(err);
//         reject(err);
//       });
//   });
// }
export async function retryConnection<T>(attempt: number, fn: Promise<T>, type: 'rabbitMQ', ms: number) {
  let currentTry = 0;
  // const a = connect<T>(fn);
  // return a
  //   .then((b) => {
  //     console.log('success');
  //     return b;
  //   })
  //   .catch((err) => {
  //     console.log(err);
  //     setTimeout(() => retryConnection, ms * 1000);
  //   });
  while (true) {
    try {
      const connection = await fn;
      console.log(`connect to ${type} succesfully`);
      return connection;
    } catch (error) {
      console.log(error);

      currentTry++;
      if (currentTry > attempt) {
        console.error(`connect to ${type} failed`);
        process.exit(1);
      }
      console.log(`connect to ${type} failed at attemp: ${currentTry}`);
      await sleep(ms);
    }
  }
}
export function start() {
  return connect(config['MESSAGE_BROKER_URL'] + '?heartbeat=10', function (err, conn: Connection) {
    if (err) {
      console.error('[AMQP]', err.message);
      // return setTimeout(start, 1000);
    }
    conn.on('error', function (err) {
      if (err.message !== 'Connection closing') {
        console.error('[AMQP] conn error', err.message);
      }
    });
    conn.on('close', function () {
      console.error('[AMQP] reconnecting');
      (async () => {
        await sleep(1000);
      })();
      start();
    });

    console.log('[AMQP] connected');
  });
}
export * from './contants';

export const encode = async (password: string) => {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
};
export const decode = async (password: string, hash: string) => {
  return await bcrypt.compare(password, hash).then((res) => res == true);
};
export const Options = (arr: any[]) => {
  let obj = {
    password: true,
  };
  arr.forEach((item) => {
    obj[item.option] = true;
  });
  return obj;
};
export function encrypt(text: string) {
  const encryption_key = crypto.randomBytes(16).toString('hex');
  const initialization_vector = crypto.randomBytes(8).toString('hex');
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(encryption_key), Buffer.from(initialization_vector))
  var crypted = cipher.update(text, 'utf8', 'hex')
  crypted += cipher.final('hex')
  return encryption_key + crypted + initialization_vector
}

export function decrypt(text: string, encryption_key: string, initialization_vector: string) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(encryption_key), Buffer.from(initialization_vector))
  let dec = decipher.update(text, 'hex', 'utf8')
  dec += decipher.final('utf8')
  return dec
}

//zod
export function splitPartsKey(text: string) {
  const middlePartLength = text.length - 32 - 16;
  return [
    text.substring(0, 32),
    text.substring(32, 32 + middlePartLength),
    text.substring(32 + middlePartLength)
  ];
}

export function arraysEqual(arr1: number[], arr2: number[]) {
  return JSON.stringify(arr1) === JSON.stringify(arr2);
}
export function extractValue(str: string, key: string) {
  const regex = new RegExp(`${key}=([^&]+)`);
  const match = regex.exec(str);
  return match ? match[1] : null;
}
export const generateRandomBase32 = (): string => {
  const buffer = crypto.randomBytes(15);
  const str = base32.encode(buffer).replace(/=/g, "").substring(0, 24);
  return str;
};
export const randomBytesAsync = promisify(generateRandomBase32);

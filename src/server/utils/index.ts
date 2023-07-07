import amqp, { Connection, connect } from 'amqplib';
import { config } from '../config';

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

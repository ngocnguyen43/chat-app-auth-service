import { createClient } from 'redis';
import { config } from '../config';

const redisURL = `redis://${config['redis_host']}`;
console.log(redisURL);
const client = createClient({ url: redisURL });
client.on('connect', () => {
  console.log('cache is connected');
});
client.on('end', () => {
  console.log('cache is disconnected');
});
client.on('error', (e) => console.log('cache error', e));
// (async () => {
//   await client.connect();
// })();
export async function publishToRedis(channel: string, message: any) {
  await client.publish(channel, JSON.stringify(message));
}
export async function subscribeToRedis(channel: string, fn: (message) => void) {
  const channel1Sub = client.duplicate();
  (async () => {
    await channel1Sub.connect();
  })();
  channel1Sub.on('message', (message) => {
    console.log(message);
  });
  // return await channel1Sub.subscribe(channel);
}

// function publishEvent(chanel: string, message: any) {
//   return nrp.emit(chanel, JSON.stringify(message));
// }
// function receiveEvent(chanel: string, message: any, callback?: () => void) {
//   return nrp.on(
//     chanel,
//     (data) => {
//       console.log(data);
//     },
//     callback,
//   );
// }
// const messageFromBE = {
//   action: 'doSomething',
//   data: 123456,
// };
// // client.on('base:test', (data) => {
// //   console.log(data);
// // });
// (async () => {
//   await publishToRedis('socket::test', messageFromBE);
// })();
export default client;

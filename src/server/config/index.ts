import { AuthnOptions, Prisma, PrismaClient, User } from '@prisma/client';

import { config } from '../../config';
import Redis from 'ioredis';

const prisma = new PrismaClient({
    log: process.env.NODE_ENV !== "production" ? ["info"] : undefined
});

const MAX_RETRY = 3;
export const redis = new Redis({
    port: config["REDIS_POST"],
    host: config["REDIS_HOST"],
    maxRetriesPerRequest: 1,
    retryStrategy(times) {
        // const delay = Math.min(times * 5, 2000);
        // return delay;
        if (times <= MAX_RETRY) {
            console.log(`Retrying connection (attempt ${times} of ${MAX_RETRY})...`);
            // You can introduce a delay here between retries if needed
            return Math.min(times * 100, 2000); // Increase the delay for each retry, with a maximum of 2 seconds
        } else {
            console.log('Max retries reached. Closing the connection.');
            return null; // Return null to indicate no more retries
        }
    },
    // reconnectOnError(err) {
    //     const targetError = 'READONLY';
    //     if (err.message.includes(targetError)) {
    //         // Only reconnect when the error contains "READONLY"
    //         return true; // or `return 1;`
    //     }
    // },
});
redis.on('error', (error) => {
    console.error('Redis connection error:', error);
});

// Optional: Listen for the 'close' event to be notified when the connection is closed
redis.on('close', () => {
    console.log('Redis connection closed.');
});
export { prisma, Prisma, User, AuthnOptions, config };

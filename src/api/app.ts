import * as dotenv from 'dotenv';
import { Express } from 'express';
import { ServerLoader } from '../api/v1/loaders';
dotenv.config();
// eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-assignment
const app: Express = ServerLoader.init();

export default app;

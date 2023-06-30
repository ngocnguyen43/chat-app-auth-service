import 'reflect-metadata';
import './auth/v1';

import compression from 'compression';
import cors from 'cors';
import * as dotenv from 'dotenv';
import express from 'express';
import helmet from 'helmet';
import { InversifyExpressServer } from 'inversify-express-utils';
import morgan from 'morgan';

import { config } from '../config';
import { container } from './container';
import { AbstractApplication } from './libs/base-application';
import { RabbitMQClient } from './message-broker';
import { router } from './health-check';
dotenv.config();
export class Application extends AbstractApplication {
  setup(): void | Promise<void> {
    const server = new InversifyExpressServer(container);
    server.setConfig((app) => {
      app.use(express.json());
      app.use(
        express.urlencoded({
          extended: true,
        }),
      );
      app.use(compression());
      app.use(morgan('dev'));
      app.use(helmet());
      app.use(
        cors({
          origin: '*',
          // credentials: true,
        }),
      );
      app.use('/health-check', router);
    });
    const app = server.build();
    app.listen(config.port, () => {
      console.log(`App is running in port ${config.port}`);
      RabbitMQClient.initialize();
    });
  }
}

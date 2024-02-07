import 'reflect-metadata';
import './auth/v1/controller/auth.controller';

import compression from 'compression';
import cors from 'cors';
import express, { NextFunction, Request, Response } from 'express';
import helmet from 'helmet';
import { InversifyExpressServer } from 'inversify-express-utils';
import morgan from 'morgan';

import { config } from '../config';
import { logger } from './common';
import { container } from './container';
import { AbstractApplication } from './libs/base-application';
import { BaseError, NotFound } from './libs/base-exception';
import { RabbitMQClient } from './message-broker';
import passport from 'passport';

export class Application extends AbstractApplication {
  constructor(
  ) {
    super();
  }
  setup(): void | Promise<void> {
    const server = new InversifyExpressServer(container);
    server.setConfig((app) => {
      app.set('trust proxy', 1);
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
          credentials: true,
          origin: ['https://' + config['ORIGIN'], 'https://www.' + config['ORIGIN'], config['ORIGIN']],
          maxAge: 86400
        }),
      );
      app.use(passport.initialize())
    });
    server.setErrorConfig((app) => {
      app.use((_: Request, res: Response, next: NextFunction) => {
        const error = new NotFound();
        next(error);
      });
      app.use((error: BaseError, _: Request, res: Response, next: NextFunction) => {
        logger.error(error.message);
        // res.header("Referrer-Policy", "no-referrer-when-downgrade")
        return res.status(error.statusCode || 500).json({
          status_code: error.statusCode || 500,
          message: error.message || 'internal server error',
        });
      });
    });

    const app = server.build();
    app.listen(config.port, () => {
      console.log(`App is running in port ${config.port}`);
      RabbitMQClient.initialize('auth-queue');
    });
  }
}

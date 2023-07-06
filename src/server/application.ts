import 'reflect-metadata';
import './auth/v1';

import compression from 'compression';
import cors from 'cors';
import * as dotenv from 'dotenv';
import express from 'express';
import helmet from 'helmet';
import { InversifyExpressServer } from 'inversify-express-utils';
import morgan from 'morgan';
import Consul, { ConsulOptions } from 'consul';
import os from 'os';
import { randomUUID } from 'crypto';
import { config } from '../config';
import { container } from './container';
import { AbstractApplication } from './libs/base-application';
import { RabbitMQClient } from './message-broker';
import { getService, logger } from './common';
dotenv.config();
export class Application extends AbstractApplication {
  constructor(
    private PID = process.pid,
    private HOST = os.hostname(),
    private PORT = config.port,
    private CONSUL_ID = `service-${HOST}-${config.port}-${randomUUID()}`,
  ) {
    super();
  }
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
      app.get('/test-client', async (req, res) => {
        const service = await getService('user-service');
        if (service) {
          const response = await (await RabbitMQClient.toClient()).clientProduce(service, req.body);
          return res.json(response);
        }
        return res.json({ error: 404 });
      });
    });

    const app = server.build();
    app.listen(config.port, () => {
      console.log(`App is running in port ${config.port}`);
      this.registerConsul();
      RabbitMQClient.initialize(this.CONSUL_ID);
    });
  }
  registerConsul() {
    const consulOptions: ConsulOptions = {
      host: '127.0.0.1',
      port: '8500',
      secure: false,
      promisify: false,
    };
    const details = {
      name: 'auth-service',
      address: this.HOST,
      check: {
        ttl: '10s',
        interval: '5s',
        deregister_critical_service_after: '1m',
      },
      port: this.PORT,
      id: this.CONSUL_ID,
    };

    const consul = new Consul(consulOptions);

    consul.agent.service.register(details, (err) => {
      if (err) {
        console.log(err);
        throw new Error(err.toString());
      }
      console.log('registered with Consul');
      setInterval(() => {
        consul.agent.check.pass({ id: `service:${this.CONSUL_ID}` }, (err: any) => {
          if (err) throw new Error(err);
          console.log('Send out heartbeat to consul');
        });
      }, 5 * 1000);

      process.on('SIGINT', () => {
        console.log('Process Terminating. De-Registering...');
        let details = { id: this.CONSUL_ID };
        consul.agent.service.deregister(details, (err) => {
          console.log('de-registered.', err);
          process.exit();
        });
      });
    });

    const watcher = consul.watch({
      method: consul.health.checks,
      options: {
        key: 'data',
      },
    });
    const known_data_instances: string[] = [];

    watcher.on('change', (data, res) => {
      console.log('received discovery update:', data);
      data.forEach((entry: any) => {
        known_data_instances.push(`http://${entry.Service.Address}:${entry.Service.Port}/`);
      });
      console.log(known_data_instances);
    });

    watcher.on('error', (err) => {
      console.error('watch error', err);
    });
  }
}

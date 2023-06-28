import compression from 'compression';
import cors from 'cors';
import express, { Express, json, urlencoded } from 'express';
import helmet from 'helmet';
import morgan from 'morgan';

export default class ServerLoader {
  public static init(): Express {
    const app: Express = express();
    app.use(json());
    app.use(
      urlencoded({
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
    return app;
  }
}

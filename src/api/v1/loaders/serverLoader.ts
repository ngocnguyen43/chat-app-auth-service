import compression from 'compression';
import express, { Express, json, urlencoded } from 'express';
import morgan from 'morgan';
import helmet from 'helmet';
import cors from 'cors';
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

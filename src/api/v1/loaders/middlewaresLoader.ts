import { Express, NextFunction, Request, Response } from 'express';

import { BaseException } from '@v1/interface';

import { InvalidEndPoint } from './Exception';

export default class MiddleWareLoader {
  public static init(app: Express) {
    app.use((req: Request, res: Response, next: NextFunction) => {
      const error = new InvalidEndPoint();
      next(error);
    });
    app.use((err: BaseException, req: Request, res: Response, next: NextFunction) => {
      return res.status(err.getStatusCode()).json({
        err: err.getErr(),
      });
    });
    return app;
  }
}

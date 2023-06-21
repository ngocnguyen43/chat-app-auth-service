import { Express, NextFunction, Request, Response } from 'express';
import { InvalidEndPoint } from './Exception';
import { BaseException } from '@v1/interface';
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

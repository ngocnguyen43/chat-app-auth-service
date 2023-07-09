import { NextFunction, Request, Response } from 'express';
import { injectable } from 'inversify';
import { BaseMiddleware } from 'inversify-express-utils';

@injectable()
export class RegisterMiddleware extends BaseMiddleware {
  public handler(req: Request, res: Response, next: NextFunction): any {
    if (req.headers['x-test']) {
      next();
    } else {
      res.status(500).json({ error: 'Facebook Auth is missing or configured incorrectly.' });
    }
  }
}

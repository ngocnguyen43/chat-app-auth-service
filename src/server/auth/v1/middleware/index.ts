import { NextFunction, Request, Response } from 'express';
import { body, validationResult } from 'express-validator';
import { injectable } from 'inversify';
import { BaseMiddleware } from 'inversify-express-utils';
import { StatusCode } from '../../../utils';
import { logger } from '../../../common';

@injectable()
export class RequestValidator extends BaseMiddleware {
  public handler(req: Request, res: Response, next: NextFunction): any {
    const validatorErrors = validationResult(req);
    if (!validatorErrors.isEmpty()) {
      logger.error(validatorErrors.array());
      return res.status(StatusCode.EXPECTATION_FAILED).json({ err: 'invalid properties' });
    }
    next();
  }
}

export const Middlewares = {
  postRegisterCheck: [
    body('email').trim().isEmail().notEmpty().withMessage('Email is required'),
    body('fullName').notEmpty().withMessage('fullname is required'),
    body('userName').notEmpty().withMessage('username is required'),
    body('password').exists().isLength({ min: 8 }).notEmpty().withMessage('password is required'),
  ],
};

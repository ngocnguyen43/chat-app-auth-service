import { NextFunction, Request, Response } from 'express';
import { body, validationResult } from 'express-validator';
import { inject, injectable } from 'inversify';
import { BaseMiddleware } from 'inversify-express-utils';
import { StatusCode } from '../../../utils';
import { logger } from '../../../common';
import { Forbidden } from '../../../libs/base-exception';
import { TYPES } from '../@types';
import { IAuhtService } from '../service/auth.service';
import jwt from "jsonwebtoken"
import { Prisma, config } from '../../../config';

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
@injectable()
export class MergeTokensMiddllware extends BaseMiddleware {
  public handler(req: Request, res: Response, next: NextFunction): any {
    const cookies = req.headers.cookie
    const userId = req.headers["x-id"] as string
    if (!userId) {
      throw new Forbidden()
    }
    if (!cookies) {
      throw new Forbidden()
    }
    req.userId = userId
    const data = cookies.split("; ")
    const objects = {};
    data.forEach(item => {
      const [key, value] = item.split('=');
      objects[key] = value;
    });
    console.log(objects["accessH"] + objects["accessS"]);

    if (!(!objects["accessH"] || !objects["accessS"] || !objects["refreshH"] || !objects["refreshS"])) {
      req.headers["authorization"] = "Bearer " + (objects["accessH"] + "." + objects["accessS"])
      req.refreshToken = objects["refreshH"] + "." + objects["refreshS"]
      return next();
    }
    throw new Forbidden()
  }
}
@injectable()
export class AccessTokenMiddleware extends BaseMiddleware {
  constructor(@inject(TYPES.AuthService) private readonly _service: IAuhtService) {
    super()
  }
  public async handler(req: Request, res: Response, next: NextFunction): Promise<any> {
    const at = req.headers.authorization.split(" ")[1];

    const userId = req.userId

    const credentials = await this._service.FindTokens(userId)
    req.userCredentials = credentials
    if (at.split(".").length !== 3)
      return res.status(StatusCode.FORBIDDEN).json({ "error": "forbidden" })
    try {
      console.log({ at, credentials });

      const verify = jwt.verify(at, credentials.publicKey);
      req.isAccessTokenExpire = false;
    } catch (error) {
      console.log(error);
      req.isAccessTokenExpire = true;
    }
    return next()
  }
}
@injectable()
export class RefreshTokenMiddleware extends BaseMiddleware {
  constructor(@inject(TYPES.AuthService) private readonly _service: IAuhtService) {
    super()
  }
  public async handler(req: Request, res: Response, next: NextFunction): Promise<any> {
    const isAccessTokenExpire = req.isAccessTokenExpire
    if (!isAccessTokenExpire) {
      console.log("no need ")
      return next();
    }

    const rt = req.refreshToken
    const credentials = req.userCredentials
    const userId = req.userId
    const isNotValidToken =
      !Object.keys(credentials).length ||
      rt.split(".").length !== 3 ||
      rt !== credentials.refreshToken ||
      (credentials.refreshTokenUsed as Prisma.JsonArray).includes(rt)

    if (isNotValidToken) {
      await this._service.ClearTokens(userId)
      return res.status(StatusCode.FORBIDDEN).json({ "error": "forbidden" })
    }

    try {
      const verify = jwt.verify(rt, credentials.publicKey);
      const { access, refresh } = await this._service.CreateAndSaveTokens(userId)
      res
        .cookie("accessH", access[0], {
          sameSite: "strict",
          secure: process.env.NODE_ENV === "production",
          domain: config["COOKIES_DOMAIN"],
          maxAge: 2 * 60 * 60 * 1000
        })
        .cookie("accessS", access[1], {
          sameSite: "strict",
          secure: process.env.NODE_ENV === "production",
          httpOnly: true,
          domain: config["COOKIES_DOMAIN"],
          maxAge: 2 * 60 * 60 * 1000
        })
        .cookie("refreshH", refresh[0], {
          sameSite: "strict",
          secure: process.env.NODE_ENV === "production",
          domain: config["COOKIES_DOMAIN"],
          maxAge: 4 * 60 * 60 * 1000
        })
        .cookie("refreshS", refresh[1],
          {
            sameSite: "strict",
            secure: process.env.NODE_ENV === "production",
            httpOnly: true,
            domain: config["COOKIES_DOMAIN"],
            maxAge: 2 * 60 * 60 * 1000
          })
      return next()
    } catch (error) {
      await this._service.ClearTokens(userId)
      return res.status(StatusCode.FORBIDDEN).json({ "error": "forbidden" })

    }
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

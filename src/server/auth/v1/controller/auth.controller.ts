import { Request, Response } from 'express';
import { inject } from 'inversify';
import { controller, httpGet, httpPost, request, requestBody, requestHeaders, response } from 'inversify-express-utils';
import jwt from 'jsonwebtoken';

import { getService } from '../../../common';
import { RabbitMQClient } from '../../../message-broker';
import { IAuhtService } from '../service/auth.service';
import { TYPES } from '../types';
import { randomUUID } from 'crypto';
import { Middlewares, RequestValidator } from '../middleware';
import {
  IGoogleLoginId,
  ILoginOptionsDto,
  IPasswordLoginDto,
  IWebAuthnLoginOptions,
  IWebAuthnLoginVerification,
  IWebAuthnRegisterOptions,
} from '@v1';

export interface RegisterDto {
  userId: string;
  email: string;
  userName: string;
  fullName: string;
  password: string;
}

@controller('/api/v1/auth')
export class AuthController {
  private rabbitMq = RabbitMQClient;
  constructor(@inject(TYPES.AuthService) private readonly _service: IAuhtService) {}
  @httpPost('/register', ...Middlewares.postRegisterCheck, RequestValidator)
  async Register(@request() req: Request, @requestBody() dto: RegisterDto, @response() res: Response) {
    dto.userId = randomUUID();
    return res.json(await this._service.Registration(dto));
  }
  @httpPost('/login-google')
  async LoginGoogle(req: Request, res: Response) {
    const target = await getService('user-service');
    let result: Record<string, any>;
    if (!target) {
      result = { err: 503 };
    } else {
      result = await this.rabbitMq.clientProduce(target, { type: 'delete-user' });
    }
    return res.json(result);
  }
  @httpPost('/login-options')
  async LoginOptions(@requestBody() dto: ILoginOptionsDto, @response() res: Response) {
    return res.json(await this._service.LoginOptions(dto.email));
  }
  @httpPost('/login-password')
  async LoginPassword(@requestBody() dto: IPasswordLoginDto, @request() req: Request, @response() res: Response) {
    const result = await this._service.PasswordLogin(dto, req.headers['x-refreshToken'] as string);
    return res.cookie('token', result['refreshToken']).json({ ok: 'ok', access_token: result['accessToken'] });
  }
  @httpPost('/login-google-id')
  async LoginGoogleId(@requestBody() dto: IGoogleLoginId, @response() res: Response) {
    return res.json(await this._service.GoogleLogin(dto.credential));
  }
  @httpPost('/webauth-registration-options')
  async WebAuthnRegistrationOptions(@requestBody() dto: IWebAuthnRegisterOptions, @response() res: Response) {
    console.log(dto);
    return res.json(await this._service.WebAuthnRegistrationOptions(dto.email));
  }
  @httpPost('/webauth-registration-verification')
  async WebAuthnRegistrationVerification(@requestBody() dto: any, @response() res: Response) {
    console.log(dto);
    return res.json(await this._service.WebAuthnRegistrationVerification(dto['data']));
  }
  @httpPost('/webauth-login-options')
  async WebAuthnLoginOptions(@requestBody() dto: IWebAuthnLoginOptions, @response() res: Response) {
    return res.json(await this._service.WebAuthnLoginOptions(dto.email));
  }
  @httpPost('/webauth-login-verification')
  async WebAuthnLoginVerification(@requestBody() dto: IWebAuthnLoginVerification, @response() res: Response) {
    console.log(dto.email);
    return res.json(await this._service.WebAuthnLoginVerification(dto.email, dto.data));
  }
  @httpGet('/test')
  async Test(@response() res: Response) {
    const result = await RabbitMQClient.clientProduce('user-queue', {
      type: 'get-user-by-email',
      payload: {
        email: 'test1@gmail.com',
      },
    });
    return res.json(result);
  }
  @httpPost('/test')
  async Testfn(@request() req: Request, @response() res: Response) {
    const publicKey =
      '-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA3n3lP9mVwX8lJjU+HR3s6nh69X1JD8njij8bBie2l8/UctBMqBbB\nD2MOtrenr6Q7rsTvvgCYQkK1OmwUrLnfDx0x2y88YVY1enTiEQbxzgsK/wczFIC9\neGXkNOVJsn7htg+sZubXLxJApabJ9dyiVVGfladuzndBDE5KDRr9albwerYTeJI8\nu1MeNn8eqjoDEp2vBnIfS281XdgVUbbi2I+OcyeUt5wZG5H5EqOAjSFRS5WlfDkf\nQJqwvTBRSdeUnzQRCEru3aMvBwdqRJtysqD9gYXzZ900mV0yKSi/iO+XuT5T4oJW\neNfV4VlpPw9q3kaTOZxHlfat4hqDb/L7AwIDAQAB\n-----END RSA PUBLIC KEY-----\n';
    // const verify = jwt.verify(req.body['token'], publicKey, { algorithms: ['RS256'] });
    return res.json(await this._service.Test());
  }
  @httpPost('/refresh-token')
  async RefreshToken(@request() req: Request, @response() res: Response) {
    return res.json(
      await this._service.RefreshToken(req.body['email'] as string, req.headers['x-refresh-token'] as string),
    );
  }
}

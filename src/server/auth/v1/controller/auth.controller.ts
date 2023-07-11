import { Request, Response } from 'express';
import { inject } from 'inversify';
import { controller, httpPost, request, requestBody, requestHeaders, response } from 'inversify-express-utils';

import { getService } from '../../../common';
import { RabbitMQClient } from '../../../message-broker';
import { IAuhtService } from '../service/auth.service';
import { TYPES } from '../types';
import { randomUUID } from 'crypto';
import { Middlewares, RequestValidator } from '../middleware';
import { ILoginOptionsDto, IPasswordLoginDto } from '@v1';

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
  async LoginPassword(@requestBody() dto: IPasswordLoginDto, @response() res: Response) {
    return res.json(await this._service.PasswordLogin(dto));
  }
  @httpPost('/login-google-id')
  async LoginGoogleId(req: Request, res: Response) {}
  @httpPost('/webauth-registration-options')
  async WebAuthnRegistrationOptions(req: Request, res: Response) {}
}

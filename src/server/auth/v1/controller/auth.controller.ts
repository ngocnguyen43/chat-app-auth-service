import { Request, Response } from 'express';
import { inject } from 'inversify';
import { controller, httpPost } from 'inversify-express-utils';

import { RabbitMQClient } from '../../../message-broker';
import { IAuhtService } from '../service/auth.service';
import { TYPES } from '../types';
import { getService } from '../../../common';

@controller('/api/v1/auth')
export class AuthController {
  private rabbitMq = RabbitMQClient;
  constructor(@inject(TYPES.AuthService) private readonly _service: IAuhtService) {}
  @httpPost('/register')
  async GetAll(req: Request, res: Response) {
    const resposne = await this._service.PasswordLogin();
    return res.json(resposne);
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
  async LoginOptions(req: Request, res: Response) {}
  @httpPost('/login-google')
  async LoginPassword(req: Request, res: Response) {}
  @httpPost('/login-google-id')
  async LoginGoogleId(req: Request, res: Response) {}
  @httpPost('/webauth-registration-options')
  async WebAuthnRegistrationOptions(req: Request, res: Response) {}
}

import { Request, Response } from 'express';
import { inject } from 'inversify';
import { controller, httpGet, httpPost } from 'inversify-express-utils';

import { RabbitMQClient } from '../../../message-broker';
import { IAuhtService } from '../service/auth.service';
import { TYPES } from '../types';

@controller('/api/v1')
export class AuthController {
  private rabbitMq = RabbitMQClient;
  constructor(@inject(TYPES.AuthService) private readonly _service: IAuhtService) {}
  @httpGet('/users')
  async GetAll(req: Request, res: Response) {
    const resposne = await this._service.PasswordLogin();
    return res.json(resposne);
  }
  @httpPost('/test')
  async Test(req: Request, res: Response) {
    console.log(req.body);
    // await this.rabbitMq
    //   .toClient('abc')
    //   .produce(req.body)
    //   .catch((err) => console.log(err));
    return res.json({ ok: true });
  }
}

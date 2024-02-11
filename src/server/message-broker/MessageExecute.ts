import { inject, injectable } from 'inversify';
import { IAuhtService, TYPES } from '../auth';
import { handleMessageError } from '../utils';

export interface IMessageExecute {
  execute(name: string, payload: any): Promise<unknown>;
  noResponseExecute(name: string, payload: any): Promise<void>;
}
@injectable()
export class MessageExecute implements IMessageExecute {
  constructor(@inject(TYPES.AuthService) private readonly _service: IAuhtService) { }
  async execute(name: string, payload: any): Promise<unknown> {
    let res: unknown;
    switch (name) {
      case 'get-user-by-id': {
        res = await this._service.GetPublicKeyFromUserId(payload['userId'] as string);
        break;
      }
      case 'get-user-by-email':
        res = { name, payload };
        break;
      case 'delete-user':
        res = { 'delete-user': 'ok' };
        break;
      case 'check-tokens':
        {
          const { user, accessToken, refreshToken } = payload as {
            user: string,
            accessToken: string,
            refreshToken: string
          }
          res = await handleMessageError(this._service.HandleTokens.bind(this._service), user, accessToken, refreshToken);
          break;
        }
      case 'test':
        res = { ok: 'OK' };
        break;
      default:
        res = { err: 404 };
    }
    return res;
  }
  async noResponseExecute(name: string, payload: any): Promise<void> {
    let res: unknown;
    switch (name) {
      case 'get-user-by-id': {
        res = await this._service.GetPublicKeyFromUserId(payload['userId'] as string);
        // res = { nah: 'nah' };
        console.log(res);
        break;
      }
      case 'get-user-by-email':
        break;
      case 'delete-user':
        this._service.DeleteUser(payload["id"] as string)
        break;
      case 'test':
        res = { ok: 'OK' };
        break;
      default:
        res = { err: 404 };
    }
  }
}

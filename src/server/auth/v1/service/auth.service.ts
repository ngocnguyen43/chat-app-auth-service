import { inject, injectable } from 'inversify';

import { getService } from '../../../common';
import { RabbitMQClient } from '../../../message-broker';
import { IAuthRepository } from '../repository/auth.repository';
import { TYPES } from '../types';

export interface IAuhtService {
  PasswordLogin: () => Promise<any>;
  Registration(): Promise<any>;
  GoogleLogin: () => Promise<any>;
  GithubLogin: () => Promise<any>;
  FacebookLogin: () => Promise<any>;
  GooglePopupLogin: () => Promise<any>;
  LoginOptions: () => Promise<any>;
  WebAuthnRegistrationOptions: () => Promise<any>;
  WebAuthnRegistrationVerification: () => Promise<any>;
  WebAuthnLoginOptions: () => Promise<any>;
  WebAuthnLoginVerification: () => Promise<any>;
}
@injectable()
export class AuthService implements IAuhtService {
  constructor(@inject(TYPES.AuthRepository) private readonly _repo: IAuthRepository) {}
  PasswordLogin = async () => {
    return await this._repo.AddPassword();
  };
  async Registration() {
    const target = await getService('user-service');
    if (target) {
      const res = await RabbitMQClient.clientProduce(target, { type: 'get-user-by-id', payload: { id: 1 } });
      return res;
    }
    return { err: 'not ok' };
  }
  GoogleLogin: () => Promise<any>;
  GithubLogin: () => Promise<any>;
  FacebookLogin: () => Promise<any>;
  GooglePopupLogin: () => Promise<any>;
  LoginOptions: () => Promise<any>;
  WebAuthnRegistrationOptions: () => Promise<any>;
  WebAuthnRegistrationVerification: () => Promise<any>;
  WebAuthnLoginOptions: () => Promise<any>;
  WebAuthnLoginVerification: () => Promise<any>;
}

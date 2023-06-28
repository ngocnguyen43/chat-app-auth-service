import { inject, injectable } from 'inversify';

import { IAuthRepository } from '../repository/auth.repository';
import { TYPES } from '../types';

export interface IAuhtService {
  PasswordLogin: () => Promise<any>;
  Registration: () => Promise<any>;
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
  Registration: () => Promise<any>;
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

import { inject, injectable } from 'inversify';

import { getService, logger } from '../../../common';
import { RabbitMQClient } from '../../../message-broker';
import { IAuthRepository } from '../repository/auth.repository';
import { TYPES } from '../types';
import { RegisterDto } from '../controller/auth.controller';
import { IPasswordLoginDto } from '@v1';
import { InternalError, NotFound } from '../../../libs/base-exception';

export interface IAuhtService {
  PasswordLogin(dto: IPasswordLoginDto): Promise<any>;
  Registration(dto: RegisterDto): Promise<any>;
  GoogleLogin(): Promise<any>;
  GithubLogin(): Promise<any>;
  FacebookLogin(): Promise<any>;
  GooglePopupLogin(): Promise<any>;
  LoginOptions(email: string): Promise<any>;
  WebAuthnRegistrationOptions(): Promise<any>;
  WebAuthnRegistrationVerification(): Promise<any>;
  WebAuthnLoginOptions(): Promise<any>;
  WebAuthnLoginVerification(): Promise<any>;
}
interface IMessageResponse {
  code: number;
  message: string;
  payload: any;
}
@injectable()
export class AuthService implements IAuhtService {
  constructor(@inject(TYPES.AuthRepository) private readonly _repo: IAuthRepository) {}
  async PasswordLogin(dto: IPasswordLoginDto) {
    const target = await getService('user-service');
    if (target) {
      const res = (await RabbitMQClient.clientProduce(target, {
        type: 'get-user-by-email',
        payload: { email: dto.email },
      })) as IMessageResponse;
      if (res.code !== 1200) {
        throw new NotFound();
      }
      // console.log(res);
      // return res;
      return await this._repo.PasswordLogin({ id: res.payload['userId'] as string, password: dto.password });
    } else {
      return { error: '' };
    }
  }
  async Registration(dto: RegisterDto) {
    const target = await getService('user-service');
    if (target) {
      const res = (await RabbitMQClient.clientProduce(target, {
        type: 'get-user-by-email',
        payload: { email: dto.email },
      })) as IMessageResponse;
      if (res.code != 1200) {
        try {
          await this._repo.CreateOne({ id: dto.userId });
          await this._repo.AddPassword({ id: dto.userId, pasword: dto.password });
          RabbitMQClient.messageProduce(target, {
            type: 'add-user',
            payload: {
              userId: dto.userId,
              email: dto.email,
              userName: dto.userName,
              fullName: dto.fullName,
            },
          });
          return { message: 'success' };
        } catch (error) {
          logger.error(error['message']);
        }
      }
      return { message: 'conflict' };
    }
    return { err: 'not ok' };
  }
  GoogleLogin = async () => {};
  GithubLogin = async () => {};
  FacebookLogin = async () => {};
  GooglePopupLogin = async () => {};
  async LoginOptions(email: string) {
    try {
      const target = await getService('user-service');
      if (target) {
        const res = (await RabbitMQClient.clientProduce(target, {
          type: 'get-user-by-email',
          payload: { email: email },
        })) as IMessageResponse;
        if (res.code !== 1200) {
          return {
            opts: {
              password: true,
            },
          };
        }
        return { opts: await this._repo.LoginOptions(res.payload['userId']) };
      } else {
        throw new InternalError();
      }
    } catch (error) {
      logger.error(error);
      throw error;
    }
  }
  WebAuthnRegistrationOptions = async () => {};
  WebAuthnRegistrationVerification = async () => {};
  WebAuthnLoginOptions = async () => {};
  WebAuthnLoginVerification = async () => {};
}

import { inject, injectable } from 'inversify';
import jwt, { UserJWTPayload } from 'jsonwebtoken';
import { getService, logger } from '../../../common';
import { RabbitMQClient } from '../../../message-broker';
import { IAuthRepository } from '../repository/auth.repository';
import { TYPES } from '../types';
import { RegisterDto } from '../controller/auth.controller';
import { IPasswordLoginDto } from '@v1';
import { InternalError, NotFound } from '../../../libs/base-exception';
import { randomUUID } from 'crypto';
import {
  GenerateAuthenticationOptionsOpts,
  GenerateRegistrationOptionsOpts,
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
  VerifyAuthenticationResponseOpts,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import base64url from 'base64url';

declare module 'jsonwebtoken' {
  interface UserJWTPayload extends jwt.JwtPayload {
    iss: string;
    nbf: number;
    aud: string;
    sub: string;
    email: string;
    email_verified: boolean;
    azp: string;
    name: string;
    picture: string;
    given_name: string;
    family_name: string;
    iat: number;
    exp: number;
    jti: string;
  }
}
export interface IAuhtService {
  PasswordLogin(dto: IPasswordLoginDto): Promise<any>;
  Registration(dto: RegisterDto): Promise<any>;
  GoogleLogin(creadential: string): Promise<any>;
  GithubLogin(): Promise<any>;
  FacebookLogin(): Promise<any>;
  GooglePopupLogin(): Promise<any>;
  LoginOptions(email: string): Promise<any>;
  WebAuthnRegistrationOptions(email: string): Promise<any>;
  WebAuthnRegistrationVerification(credential: any): Promise<any>;
  WebAuthnLoginOptions(email: string): Promise<any>;
  WebAuthnLoginVerification(email: string, data: any): Promise<any>;
  Test(): Promise<any>;
}
interface IMessageResponse {
  code: number;
  message: string;
  payload: any;
}
type ValidOption = [object[], string];
@injectable()
export class AuthService implements IAuhtService {
  constructor(@inject(TYPES.AuthRepository) private readonly _repo: IAuthRepository) {}
  async Test(): Promise<any> {
    const target = await getService('user-service');
    return await RabbitMQClient.clientProduce(target, { type: 'test' });
  }
  private checkValidOption(value: ValidOption, federation: ValidOption) {
    return (
      value[0].some((item) => item.hasOwnProperty(value[1])) &&
      federation[0].some((item) => item.hasOwnProperty(federation[1]))
    );
  }
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
  async GoogleLogin(credential: string) {
    const decoded = jwt.decode(credential) as UserJWTPayload;
    const target = await getService('user-service');
    if (!target) {
      throw new InternalError();
    }
    const res = (await RabbitMQClient.clientProduce(target, {
      type: 'get-user-by-email',
      payload: { email: decoded.email },
    })) as IMessageResponse;
    const userId = randomUUID();
    if (res.code !== 1200) {
      try {
        RabbitMQClient.messageProduce(target, {
          type: 'add-user',
          payload: {
            userId: userId,
            email: decoded.email,
            fullName: decoded.given_name + ' ' + decoded.family_name,
          },
        });
        //add user
        await this._repo.CreateOne({ id: userId });
        //add google in authn_opotions
        await this._repo.AddGoogle({ id: userId, email: decoded.email, aud: decoded.aud });
        //return
        return { fullname: decoded.given_name + ' ' + decoded.family_name, email: decoded.email };
      } catch (error) {
        console.log(error);
        throw error;
      }
    }

    const option = await this._repo.FindOneWithKeyValue(res.payload['userId'], 'google', 'oauth');
    if (option && this.checkValidOption([option.key['value'], 'google'], [option.key['federated'], 'google'])) {
      return { fullname: decoded.family_name + decoded.given_name, email: decoded.email };
    }
    await this._repo.AddGoogle({ id: res.payload['userId'], email: decoded.email, aud: decoded.aud });
    return { fullname: decoded.family_name + decoded.given_name, email: decoded.email };
  }
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
  async WebAuthnRegistrationOptions(email: string) {
    const target = await getService('user-service');
    if (!target) {
      throw new InternalError();
    }
    const res = (await RabbitMQClient.clientProduce(target, {
      type: 'get-user-by-email',
      payload: {
        email: email,
      },
    })) as IMessageResponse;
    if (res.code !== 1200) {
      throw new InternalError();
    }
    const authn = await this._repo.FindOneByUserId(res.payload['userId'], 'passkey');
    const options: GenerateRegistrationOptionsOpts = {
      rpName: 'Chat App',
      rpID: 'localhost',
      userID: email,
      userName: res.payload['fullName'],
      timeout: 60000,
      attestationType: 'none',
      excludeCredentials: authn
        ? (authn.key['devices'] as []).map((dev: any) => ({
            id: dev.credentialID,
            type: 'public-key',
            transports: dev.transports,
          }))
        : [],
      authenticatorSelection: {
        userVerification: 'required',
        residentKey: 'required',
      },
      supportedAlgorithmIDs: [-7, -257],
    };
    const regOptions = generateRegistrationOptions(options);
    await this._repo.AddChallenge(res.payload['userId'], regOptions.challenge);
    return regOptions;
  }
  async WebAuthnRegistrationVerification(credential: any) {
    try {
      const target = await getService('user-service');
      if (!target) {
        throw new InternalError();
      }
      const res = (await RabbitMQClient.clientProduce(target, {
        type: 'get-user-by-email',
        payload: credential['user']['email'],
      })) as IMessageResponse;
      if (res.code !== 1200) {
        throw new InternalError();
      }
      const userId = res.payload['userId'];
      const data = credential['loginRes'];
      const auth = await this._repo.FindOneByUserId(userId, 'passkey');
      const user = await this._repo.GetUserById(userId);
      const expectedChallenge = user.currentChallenge;
      let verification: VerifiedRegistrationResponse;
      const options = {
        response: data,
        expectedChallenge: `${expectedChallenge}`,
        expectedOrigin: ['http://localhost:5173', 'https://localhost:5173'],
        expectedRPID: 'localhost',
        requireUserVerification: true,
      };
      verification = await verifyRegistrationResponse(options);
      const { verified, registrationInfo } = verification;
      if (verified && registrationInfo) {
        const { credentialPublicKey, credentialID, counter } = registrationInfo;
        // console.log('check credentailID:::', credentialID);
        const existingDevice = auth
          ? (auth.key['devices'] as []).find((device: any) => Buffer.from(device.credentialID).equals(credentialID))
          : false;
        if (!auth) {
          const newDevice = {
            credentialPublicKey: Array.from(credentialPublicKey),
            credentialID: Array.from(credentialID),
            counter,
            transports: data.response.transports,
          };
          await this._repo.CreateDevice(userId, newDevice);
          console.log(newDevice);
        } else {
          if (!existingDevice) {
            const newDevice = {
              credentialPublicKey: Array.from(credentialPublicKey),
              credentialID: Array.from(credentialID),
              counter,
              transports: data.response.transports,
            };
            await this._repo.AddDevice(auth.id, userId, newDevice);
            console.log(newDevice);
          }
        }
      }
      return { ok: true };
    } catch (error) {
      console.log(error);
      return { ok: 'not ok' };
    }
  }
  async WebAuthnLoginOptions(email: string) {
    try {
      const target = await getService('user-service');
      if (!target) {
        throw new InternalError();
      }
      const res = (await RabbitMQClient.clientProduce(target, {
        type: 'get-user-by-email',
        payload: {
          email: email,
        },
      })) as IMessageResponse;
      if (res.code !== 1200) {
        throw new InternalError();
      }
      const authn = await this._repo.FindOneByUserId(res.payload['userId'], 'passkey');
      const options: GenerateAuthenticationOptionsOpts = {
        timeout: 60000,
        allowCredentials: authn
          ? (authn.key['devices'] as []).map((device: any) => ({
              id: device.credentialID,
              type: 'public-key',
              // Optional
              transports: device.transports,
            }))
          : [],
        // userVerification: 'required',
        userVerification: 'preferred',
        rpID: 'localhost',
      };
      const loginOpts = generateAuthenticationOptions(options);
      const challenge = loginOpts.challenge;
      await this._repo.AddChallenge(res.payload['userId'], challenge);
      return loginOpts;
    } catch (error) {
      console.log(error);
      return { err: 'errr' };
    }
  }
  async WebAuthnLoginVerification(email: string, data: any) {
    const target = await getService('user-service');
    if (!target) {
      throw new InternalError();
    }
    const res = (await RabbitMQClient.clientProduce(target, {
      type: 'get-user-by-email',
      payload: {
        email: email,
      },
    })) as IMessageResponse;
    if (res.code !== 1200) {
      throw new InternalError();
    }
    const userId = res.payload['userId'];
    const authn = await this._repo.FindOneByUserId(userId, 'passkey');
    const user = await this._repo.GetUserById(userId);
    const expectedChallenge = user.currentChallenge;
    let dbAuthenticator;
    const bodyCredIDBuffer = base64url.toBuffer(data['rawId']);
    // console.log(data);
    for (const device of authn.key['devices']) {
      const currentCredential = Buffer.from(device.credentialID);
      if (bodyCredIDBuffer.equals(currentCredential)) {
        dbAuthenticator = device;
        break;
      }
    }
    if (!dbAuthenticator) {
      return { ok: false };
    }
    let verification: VerifiedAuthenticationResponse;
    try {
      const options: VerifyAuthenticationResponseOpts = {
        response: data,
        expectedChallenge: `${expectedChallenge}`,
        expectedOrigin: ['http://localhost:5173', 'https://localhost:5173'],
        expectedRPID: 'localhost',
        authenticator: {
          ...dbAuthenticator,
          credentialPublicKey: Buffer.from(dbAuthenticator.credentialPublicKey), // Re-convert to Buffer from JSON
        },
        requireUserVerification: true,
      };
      verification = await verifyAuthenticationResponse(options);
    } catch (error) {
      console.log(error);
      throw new InternalError();
    }
    const { verified, authenticationInfo } = verification;
    // console.log('check verify:::::', { verified, authenticationInfo });
    // const passkeys = (await AuthOptionsRepository.FindPasskeys(user.id)) as [];
    // console.log(Buffer.from(passkeys.at(1)['credentialID']).equals(bodyCredIDBuffer));
    // console.log(bodyCredIDBuffer);
    if (verified) {
      await this._repo.UpdatePasskeyCounter(authn.id, user.id, data['rawId'], authenticationInfo.newCounter);
    }
    return { ok: true };
  }
}

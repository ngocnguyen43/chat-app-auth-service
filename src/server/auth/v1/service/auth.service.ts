import { inject, injectable } from 'inversify';
import jwt, { UserJWTPayload } from 'jsonwebtoken';
import { getService, logger } from '../../../common';
import { RabbitMQClient } from '../../../message-broker';
import { IAuthRepository } from '../repository/auth.repository';
import { TYPES } from '../@types';
import { RegisterDto } from '../controller/auth.controller';
import { IPasswordLoginDto } from '@v1';
import { InternalError, NotFound, WrongPassword } from '../../../libs/base-exception';
import { generateKeyPairSync, randomUUID } from 'crypto';
import util from 'util';

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
import { ITokenRepository } from '../repository/token.repository';
import { decode } from '../../../utils';
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
  PasswordLogin(dto: IPasswordLoginDto, token: string): Promise<any>;
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
  RefreshToken(email: string, refershToken: string): Promise<any>;
  Test(): Promise<any>;
  GetPublicKeyFromUserId(id: string): Promise<string>;
  TestCnt(): Promise<void>
}
interface IMessageResponse {
  code: number;
  message: string;
  payload: any;
}
type ValidOption = [object[], string];
export const verifyPromise = () => {
  util.promisify(jwt.verify);
};

@injectable()
export class AuthService implements IAuhtService {
  constructor(
    @inject(TYPES.AuthRepository) private readonly _authRepo: IAuthRepository,
    @inject(TYPES.TokenRepository) private readonly _tokenRepo: ITokenRepository,
  ) { }
  async TestCnt(): Promise<void> {
    await this._authRepo.TestCnt()
  }
  async GetPublicKeyFromUserId(id: string): Promise<string> {
    try {
      const publicKey = await this._tokenRepo.GetPublicKeyFromId(id);
      return publicKey;
    } catch (error) {
      console.log(error);
      return 'nah';
    }
  }
  async RefreshToken(email: string, refershToken: string): Promise<any> {
    const res = (await RabbitMQClient.clientProduce('user-queue', {
      type: 'get-user-by-email',
      payload: { email: email },
    })) as IMessageResponse;
    if (res.code !== 1200) {
      throw new NotFound();
    }
    const tokens = await this._tokenRepo.FindTokensByUserId(res.payload['userId']);
    try {
      const verify = jwt.verify(refershToken, tokens.publicKey);
      console.log(verify);
      return verify;
    } catch (error) {
      console.log(error['message']);
      return { err: 'err' };
    }
  }
  async Test(): Promise<any> {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'pkcs1',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs1',
        format: 'pem',
      },
    });
    const token = jwt.sign('hello', publicKey, { algorithm: 'RS256' });
    return { token: token };
  }
  private checkValidOption(value: ValidOption, federation: ValidOption) {
    return (
      value[0].some((item) => item.hasOwnProperty(value[1])) &&
      federation[0].some((item) => item.hasOwnProperty(federation[1]))
    );
  }
  async PasswordLogin(dto: IPasswordLoginDto, refresh: string) {
    const res = (await RabbitMQClient.clientProduce('user-queue', {
      type: 'get-user-by-email',
      payload: { email: dto.email },
    })) as IMessageResponse;
    if (res.code !== 1200) {
      throw new NotFound();
    }
    const decoded = await this._authRepo.FindPasswordByUserId(res.payload['userId']);
    if (decoded) {
      const isSimilar = await decode(dto.password, decoded);
      if (!isSimilar) {
        throw new WrongPassword();
      }
      const { privateKey, publicKey } = this._tokenRepo.CreateKeysPair();
      const { accessToken, refreshToken } = this._tokenRepo.CreateTokens(res.payload, privateKey);
      await this._tokenRepo.SaveTokens(res.payload['userId'], publicKey, refreshToken);
      return { ok: 'OK', res: res['payload'], accessToken, refreshToken };
    }
    throw new WrongPassword();
  }
  async Registration(dto: RegisterDto) {
    const res = (await RabbitMQClient.clientProduce('user-queue', {
      type: 'get-user-by-email',
      payload: { email: dto.email },
    })) as IMessageResponse;
    if (res.code != 1200) {
      try {
        await this._authRepo.CreateOne({ id: dto.userId, createdAt: dto.createdAt, updatedAt: dto.updatedAt });
        await this._authRepo.AddPassword({ id: dto.userId, pasword: dto.password });
        RabbitMQClient.messageProduce('user-queue', {
          type: 'add-user',
          payload: {
            userId: dto.userId,
            email: dto.email,
            userName: dto.userName,
            fullName: dto.fullName,
            createdAt: dto.createdAt,
            updatedAt: dto.updatedAt
          },
        });
        RabbitMQClient.messageProduce('chat-queue', {
          type: 'add-user',
          payload: {
            userId: dto.userId,
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
        const unixTimestamp = Date.now().toString();
        await this._authRepo.CreateOne({ id: userId, createdAt: unixTimestamp, updatedAt: unixTimestamp });
        //add google in authn_opotions
        await this._authRepo.AddGoogle({ id: userId, email: decoded.email, aud: decoded.aud });
        //return
        return { fullname: decoded.given_name + ' ' + decoded.family_name, email: decoded.email };
      } catch (error) {
        console.log(error);
        throw error;
      }
    }

    const option = await this._authRepo.FindOneWithKeyValue(res.payload['userId'], 'google', 'oauth');
    if (option && this.checkValidOption([option.key['value'], 'google'], [option.key['federated'], 'google'])) {
      return { fullname: decoded.family_name + decoded.given_name, email: decoded.email };
    }
    await this._authRepo.AddGoogle({ id: res.payload['userId'], email: decoded.email, aud: decoded.aud });
    return { fullname: decoded.family_name + decoded.given_name, email: decoded.email };
  }
  GithubLogin = async () => { };
  FacebookLogin = async () => { };
  GooglePopupLogin = async () => { };
  async LoginOptions(email: string) {
    try {
      const target = await getService('user-service');
      console.log(target)
      if (target) {
        const res = (await RabbitMQClient.clientProduce("user-queue", {
          type: 'get-user-by-email',
          payload: { email: email },
        })) as IMessageResponse;
        console.log(res)
        if (res.code !== 1200) {
          return {
            opts: {
              password: true,
            },
          };
        }
        return { opts: await this._authRepo.LoginOptions(res.payload['userId']) };
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
    const authn = await this._authRepo.FindOneByUserId(res.payload['userId'], 'passkey');
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
    await this._authRepo.AddChallenge(res.payload['userId'], regOptions.challenge);
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
      const auth = await this._authRepo.FindOneByUserId(userId, 'passkey');
      const user = await this._authRepo.GetUserById(userId);
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
          await this._authRepo.CreateDevice(userId, newDevice);
          console.log(newDevice);
        } else {
          if (!existingDevice) {
            const newDevice = {
              credentialPublicKey: Array.from(credentialPublicKey),
              credentialID: Array.from(credentialID),
              counter,
              transports: data.response.transports,
            };
            await this._authRepo.AddDevice(auth.id, userId, newDevice);
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
      const res = (await RabbitMQClient.clientProduce("user-queue", {
        type: 'get-user-by-email',
        payload: {
          email: email,
        },
      })) as IMessageResponse;
      if (res.code !== 1200) {
        throw new InternalError();
      }
      const authn = await this._authRepo.FindOneByUserId(res.payload['userId'], 'passkey');
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
      await this._authRepo.AddChallenge(res.payload['userId'], challenge);
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
    const authn = await this._authRepo.FindOneByUserId(userId, 'passkey');
    const user = await this._authRepo.GetUserById(userId);
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
      await this._authRepo.UpdatePasskeyCounter(authn.id, user.id, data['rawId'], authenticationInfo.newCounter);
    }
    return { ok: true };
  }
}

import { id, inject, injectable } from 'inversify';
import jwt from 'jsonwebtoken';
import { logger } from '../../../common';
import { RabbitMQClient } from '../../../message-broker';
import { IAuthRepository } from '../repository/auth.repository';
import { FacebookUserType, GithubUserType, GoogleUserType, IMessageResponse, IPasswordLoginDto, JwtVerifyType, StrictUnion, TYPES, ValidOption } from '../@types';
import { RegisterDto } from '../controller/auth.controller';
import { InternalError, InvalidCredentials, NotFound, WrongCredentials, WrongPassword } from '../../../libs/base-exception';
import { generateKeyPairSync, randomUUID } from 'crypto';
import { toDataURL } from "qrcode"
import * as OTPAuth from "otpauth";

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
import { decode, decrypt, generateRandomBase32, randomBytesAsync, splitPartsKey } from '../../../utils';
import { config } from '../../../config';
export interface IAuhtService {
  ClearTokens(id: string): Promise<void>
  ClearRefreshTokensUsed(id: string): Promise<void>
  HandleTokens(id: string, accessToken: string, refreshToken: string): Promise<any>;
  PasswordLogin(dto: IPasswordLoginDto): Promise<{ access: string[], refresh: string[] }>;
  Registration(dto: RegisterDto): ReturnType<IAuhtService["PasswordLogin"]>;
  LoginOptions(email: string): Promise<any>;
  WebAuthnRegistrationOptions(email: string): Promise<any>;
  WebAuthnRegistrationVerification(credential: any): Promise<any>;
  WebAuthnLoginOptions(email: string): Promise<any>;
  WebAuthnLoginVerification(email: string, data: any): Promise<{
    access: string[];
    refresh: string[];
    userId: any;
  }>;
  Test(): Promise<any>;
  GetPublicKeyFromUserId(id: string): Promise<string>;
  TestCnt(): Promise<void>
  HandleCredential(user: StrictUnion<GoogleUserType | GithubUserType | FacebookUserType>): Promise<{ isFirstLogin: boolean, userId?: string }>
  UpdateStatusLogin(id: string, provider: string): Promise<void>
  DeleteUser(id: string): Promise<void>
  HandleSetupCredential(ssid: string, provider: string, email: string | null): Promise<any>
  FindPasskeys(email: string): Promise<any>
  DeletePasskeys(base64string: string, userId: string): Promise<void>
  ChangePassword(email: string, oldPssword: string, newPassword: string): Promise<void>
  Create2FA(email: string): Promise<string>
  Enable2FA(email: string, token: string): Promise<void>
  Find2Fa(email: string): Promise<{ "2fa": boolean }>
  Delete2FA(email: string): Promise<void>
  Validate2FA(email: string, token: string): Promise<void>
  FindTokens(id: string): Promise<ReturnType<ITokenRepository["FindTokensByUserId"]>>
  CreateAndSaveTokens(id: string): Promise<{
    access: string[];
    refresh: string[];
  }>
  GetUserByEmail(email: string): Promise<string>
}

@injectable()
export class AuthService implements IAuhtService {
  constructor(
    @inject(TYPES.AuthRepository) private readonly _authRepo: IAuthRepository,
    @inject(TYPES.TokenRepository) private readonly _tokenRepo: ITokenRepository,
  ) { }
  async ClearRefreshTokensUsed(id: string): Promise<void> {
    const existTokens = await this._tokenRepo.FindTokensByUserId(id);
    if (!existTokens) return
    await this._tokenRepo.ClearRefreshTokensUsed(id)
  }
  async GetUserByEmail(email: string): Promise<string> {
    const res = (await RabbitMQClient.clientProduce('user-queue', {
      type: 'get-user-by-email',
      payload: { email },
    })) as IMessageResponse;

    return res.payload["userId"]
  }
  async HandleTokens(id: string, accessToken: string, refreshToken: string) {
    const credentials = await this.FindTokens(id);
    try {
      const verify = jwt.verify(accessToken, credentials.publicKey) as JwtVerifyType
      return { id: verify.sub, access: null, refresh: null };
    } catch (error) {
    }
    try {
      const verify = jwt.verify(refreshToken, credentials.publicKey) as JwtVerifyType
      const tokens = await this.CreateAndSaveTokens(id)
      return { id: verify.sub, ...tokens };
    } catch (error) {
      this.ClearTokens(id)
      throw new InvalidCredentials();
    }
  }
  async ClearTokens(id: string): Promise<void> {
    return await this._tokenRepo.ClearToken(id)
  }
  async FindTokens(id: string): Promise<ReturnType<ITokenRepository["FindTokensByUserId"]>> {
    return await this._tokenRepo.FindTokensByUserId(id)
  }

  async Validate2FA(email: string, token: string): Promise<void> {
    const res = (await RabbitMQClient.clientProduce('user-queue', {
      type: 'get-user-by-email',
      payload: { email },
    })) as IMessageResponse
    if (res.code !== 1200) {
      throw new WrongCredentials()
    }
    const existCredential = await this._authRepo.FindOneFAWithSecret(res.payload["userId"])
    const exist2FA = await this._authRepo.FindOneFA(res.payload["userId"])
    if (!exist2FA || !existCredential) {
      throw new WrongPassword()
    }
    const totp = new OTPAuth.TOTP({
      issuer: config["ORIGIN"],
      label: email,
      algorithm: "SHA1",
      digits: 6,
      secret: existCredential.secret!,
    });

    const delta = totp.validate({ token, window: 1 });

    if (delta === null) {
      throw new WrongCredentials()
    }
    return
  }
  async Delete2FA(email: string): Promise<void> {
    const res = (await RabbitMQClient.clientProduce('user-queue', {
      type: 'get-user-by-email',
      payload: { email },
    })) as IMessageResponse
    if (res.code !== 1200) {
      throw new WrongCredentials()
    }
    const exist2fa = await this._authRepo.FindOneFA(res.payload["userId"])
    if (!exist2fa) {
      return
    }
    await this._authRepo.Delete2FA(exist2fa)
  }
  async Find2Fa(email: string): Promise<{ "2fa": boolean }> {
    const res = (await RabbitMQClient.clientProduce('user-queue', {
      type: 'get-user-by-email',
      payload: { email },
    })) as IMessageResponse
    if (res.code !== 1200) {
      return { "2fa": false }
    }
    const exist2fa = await this._authRepo.FindOneFAWithSecret(res.payload["userId"])
    if (!exist2fa) {
      return { "2fa": false }
    }
    return { "2fa": exist2fa.enable }
  }
  async Enable2FA(email: string, token: string): Promise<void> {
    const res = (await RabbitMQClient.clientProduce('user-queue', {
      type: 'get-user-by-email',
      payload: { email },
    })) as IMessageResponse
    if (res.code !== 1200) {
      throw new WrongCredentials()
    }
    const existCredential = await this._authRepo.FindOneFAWithSecret(res.payload["userId"])
    const exist2FA = await this._authRepo.FindOneFA(res.payload["userId"])
    if (!exist2FA || !existCredential) {
      throw new WrongPassword()
    }
    const totp = new OTPAuth.TOTP({
      issuer: config["ORIGIN"],
      label: email,
      algorithm: "SHA1",
      digits: 6,
      secret: existCredential.secret!,
    });

    const delta = totp.validate({ token, window: 1 });

    if (delta === null) {
      throw new WrongCredentials()
    }
    await this._authRepo.Update2FA(exist2FA, existCredential.secret, true)
  }
  async Create2FA(email: string): Promise<string> {
    const res = (await RabbitMQClient.clientProduce('user-queue', {
      type: 'get-user-by-email',
      payload: { email },
    })) as IMessageResponse
    if (res.code !== 1200) {
      throw new WrongCredentials()
    }
    const exist2FA = await this._authRepo.FindOneFA(res.payload["userId"])

    const secret = generateRandomBase32()
    const uuid = randomUUID()
    if (exist2FA) {
      await this._authRepo.Update2FA(exist2FA, secret, false)
    } else {
      await this._authRepo.Create2FA(uuid, res.payload["userId"], secret)
    }
    try {
      const totp = new OTPAuth.TOTP({
        issuer: config["ORIGIN"],
        label: email,
        algorithm: "SHA1",
        digits: 6,
        secret
      });
      return await toDataURL(totp.toString())
    } catch (error) {
      console.log(error);
      return ""

    }
  }
  async ChangePassword(email: string, oldPssword: string, newPassword: string): Promise<void> {
    const res = (await RabbitMQClient.clientProduce('user-queue', {
      type: 'get-user-by-email',
      payload: { email },
    })) as IMessageResponse
    if (res.code !== 1200) {
      throw new WrongCredentials()
    }
    const decodedPassword = await this._authRepo.FindPasswordByUserId(res.payload['userId']);
    if (decodedPassword) {
      const isOldPasswordValid = await decode(oldPssword, decodedPassword)
      if (!isOldPasswordValid) {
        throw new WrongCredentials();
      }
      await this._authRepo.UpdatePassword(newPassword, res.payload['userId'])
    }
  }
  async DeletePasskeys(base64string: string, userId: string): Promise<void> {
    await this._authRepo.DeletePasskeys(base64string, userId)
  }
  async FindPasskeys(email: string): Promise<any> {
    const res = (await RabbitMQClient.clientProduce('user-queue', {
      type: 'get-user-by-email',
      payload: { email: email },
    })) as IMessageResponse;
    if (res.code !== 1200) {
      throw new InternalError()
    }
    const userId = res.payload['userId'];
    const passkeys = await this._authRepo.FindPasskeys(userId)
    const credentialIDs = passkeys.devices.map(i => {
      return {
        credential: i.credentialID,
        createdAt: i.createdAt
      }
    })
    const base64s = credentialIDs.map(i => {
      const binaryString = String.fromCharCode(...i.credential)
      return { id: btoa(binaryString), createdAt: i.createdAt };
    })
    return base64s
  }
  async HandleSetupCredential(ssid: string, provider: string, email: string | null): Promise<any> {
    const splitSsid = splitPartsKey(ssid)

    const userId = decrypt(splitSsid[1], splitSsid[0], splitSsid[2])
    // res = (await RabbitMQClient.clientProduce('user-queue', {
    //   type: 'get-user-by-provider',
    //   payload: { provider, id: userId },
    // })) as IMessageResponse;
    let res: IMessageResponse
    let userKey: { provider: string; isLoginBefore: boolean; };
    if (provider === "google") {
      res = (await RabbitMQClient.clientProduce('user-queue', {
        type: 'get-user-by-email',
        payload: { email: decodeURIComponent(email) },
      })) as IMessageResponse;
      userKey = await this._authRepo.CheckLoginBefore(res.payload["userId"], "google")
      // try {
      //   const { privateKey, publicKey } = this._tokenRepo.CreateKeysPair();
      //   const { accessToken, refreshToken } = this._tokenRepo.CreateTokens(res.payload["userId"], privateKey);
      //   await this._tokenRepo.SaveTokens(res.payload['userId'], publicKey, refreshToken);
      //   return { isLoginBefore: userKey.isLoginBefore, ...res['payload'], id: res["payload"]["userId"], picture: user.picture, provider: "google", accessToken, refreshToken };
      // } catch (error) {
      //   console.log(error)
      // }
    }
    else if (provider === "facebook") {
      res = (await RabbitMQClient.clientProduce('user-queue', {
        type: 'get-user-by-provider',
        payload: { provider: provider, id: decodeURIComponent(userId) },
      })) as IMessageResponse;

      userKey = await this._authRepo.CheckLoginBefore(res.payload["userId"], "facebook")
      // try {
      //   const { privateKey, publicKey } = this._tokenRepo.CreateKeysPair();
      //   const { accessToken, refreshToken } = this._tokenRepo.CreateTokens(res.payload["userId"], privateKey);
      //   await this._tokenRepo.SaveTokens(res.payload['userId'], publicKey, refreshToken);
      //   return { isLoginBefore: userKey.isLoginBefore, ...res['payload'], id: res["payload"]["userId"], picture: "https://d3lugnp3e3fusw.cloudfront.net/143086968_2856368904622192_1959732218791162458_n.png", provider: "github", accessToken, refreshToken };
      // } catch (error) {
      //   console.log(error)
      // }
    } else if (provider === "github") {
      res = (await RabbitMQClient.clientProduce('user-queue', {
        type: 'get-user-by-provider',
        payload: { provider: provider, id: decodeURIComponent(userId) },
      })) as IMessageResponse;
      userKey = await this._authRepo.CheckLoginBefore(res.payload["userId"], "github")

    }
    const { privateKey, publicKey } = this._tokenRepo.CreateKeysPair();
    const { accessToken, refreshToken } = this._tokenRepo.CreateTokens(res.payload["userId"], privateKey);
    await this._tokenRepo.SaveTokens(res.payload['userId'], publicKey, refreshToken);
    return { isLoginBefore: userKey.isLoginBefore, id: res.payload["userId"], provider, accessToken, refreshToken, ...res.payload }
  }
  async DeleteUser(id: string): Promise<void> {
    try {
      await this._authRepo.DeleteUser(id)
    } catch (error) {
      console.log(error)
    }
  }
  async UpdateStatusLogin(id: string, provider: string) {
    await this._authRepo.UpdateStatusLogin(id, provider)
  }
  async HandleSigninGoogle(dto: { email: string, userName: string, fullName: string, picture: string }) {
    try {
      const id = randomUUID()
      const { email, userName, fullName, picture } = dto
      RabbitMQClient.messageProduce('user-queue', {
        type: 'add-user',
        payload: {
          userId: id,
          email,
          userName,
          fullName,
          createdAt: Date.now().toString(),
          updatedAt: Date.now().toString()
        },
      });
      RabbitMQClient.messageProduce('chat-queue', {
        type: 'add-user',
        payload: {
          userId: id,
          fullName: fullName,
        },
      });
      RabbitMQClient.messageProduce("user-queue", {
        type: "create-user-avatar",
        payload: {
          id,
          avatar: encodeURIComponent(picture),
          bio: ""
        }
      })
      await this._authRepo.CreateOne({ id, createdAt: Date.now().toString(), updatedAt: Date.now().toString() });
      await this._authRepo.AddOauth2(id, "google")
      return id
    } catch (error) {
      console.log(error)
      throw new WrongCredentials()
    }
  }
  async HandleSigninFacebook(dto: { id: string, displayName: string, picture: string }) {
    try {
      const userId = randomUUID()
      const { id, displayName: fullName, picture } = dto
      RabbitMQClient.messageProduce('user-queue', {
        type: 'add-user-provider',
        payload: {
          userId,
          provider: {
            provider: "facebook",
            id
          },
          userName: fullName,
          fullName,
          createdAt: Date.now().toString(),
          updatedAt: Date.now().toString()
        },
      });
      RabbitMQClient.messageProduce('chat-queue', {
        type: 'add-user',
        payload: {
          userId,
          fullName,
        },
      });
      RabbitMQClient.messageProduce("user-queue", {
        type: "create-user-avatar",
        payload: {
          id: userId,
          avatar: encodeURIComponent(picture),
          bio: ""
        }
      })
      await this._authRepo.CreateOne({ id: userId, createdAt: Date.now().toString(), updatedAt: Date.now().toString() });
      await this._authRepo.AddOauth2(userId, "facebook")
      return userId
    } catch (error) {
      console.log(error)
      throw new WrongCredentials()
    }
  }
  async HandleSigninGithub(dto: { id: string, displayName: string, picture: string }) {
    try {
      const { id, displayName: fullName, picture } = dto
      RabbitMQClient.messageProduce('user-queue', {
        type: 'add-user-provider',
        payload: {
          userId: id,
          provider: {
            provider: "github",
            id
          },
          userName: fullName,
          fullName,
          createdAt: Date.now().toString(),
          updatedAt: Date.now().toString()
        },
      });
      RabbitMQClient.messageProduce('chat-queue', {
        type: 'add-user',
        payload: {
          userId: id,
          fullName,
        },
      });
      RabbitMQClient.messageProduce("user-queue", {
        type: "create-user-avatar",
        payload: {
          id,
          avatar: encodeURIComponent(picture),
          bio: ""
        }
      })
      await this._authRepo.CreateOne({ id, createdAt: Date.now().toString(), updatedAt: Date.now().toString() });
      await this._authRepo.AddOauth2(id, "github")
      return {
        isLoginBefore: false,
        id,
        picture,
        fullName,
        userName: fullName,
        provider: "github"
      };
    } catch (error) {
      console.log(error)
      throw new WrongCredentials()
    }
  }
  async HandleCredential(user: StrictUnion<GoogleUserType | GithubUserType | FacebookUserType>): Promise<{ isFirstLogin: boolean, userId?: string }> {

    if (!user.provider) {
      const res = (await RabbitMQClient.clientProduce('user-queue', {
        type: 'get-user-by-email',
        payload: { email: user.email },
      })) as IMessageResponse;
      if (res.code !== 1200) {
        const id = await this.HandleSigninGoogle({ email: user.email, userName: (user.given_name) as string + " " + (user.family_name as string), fullName: (user.given_name) as string + " " + (user.family_name as string), picture: user.picture })
        return { isFirstLogin: true, userId: id }
      }
      return { isFirstLogin: false, userId: res.payload["userId"] }

    }
    else if (user.provider === "facebook") {
      const res = (await RabbitMQClient.clientProduce('user-queue', {
        type: 'get-user-by-provider',
        payload: { provider: user.provider, id: user.id },
      })) as IMessageResponse;
      if (res.code !== 1200) {
        const userId = await this.HandleSigninFacebook({ id: user.id, displayName: user.displayName, picture: "https://d3lugnp3e3fusw.cloudfront.net/143086968_2856368904622192_1959732218791162458_n.png" })
        return { isFirstLogin: true, userId }

      }
      return { isFirstLogin: false, userId: res.payload["userId"] }

    } else if (user.provider === "github") {
      const res = (await RabbitMQClient.clientProduce('user-queue', {
        type: 'get-user-by-provider',
        payload: { provider: user.provider, id: user.id },
      })) as IMessageResponse;
      if (res.code !== 1200) {
        await this.HandleSigninGithub({ id: user.id, displayName: user.displayName, picture: user.photos[0].value })
        return { isFirstLogin: true }
      }
      return { isFirstLogin: false }

    }

  }
  async TestCnt(): Promise<void> {
    try {

      await this._authRepo.TestCnt()
    } catch (error) {
      console.log(error);

    }
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
  SplitToken(token: string) {
    const splitted = token.split(".")
    if (splitted.length !== 3) throw new InternalError()
    return [splitted.splice(0, 2).join("."), splitted.at(-1)]
  }
  async PasswordLogin(dto: IPasswordLoginDto) {
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
      const tokens = await this.CreateAndSaveTokens(res.payload["userId"])

      return { ...tokens }
      // return { ok: 'OK', res: res['payload'], accessToken, refreshToken };
    }
    throw new WrongPassword();
  }
  async CreateAndSaveTokens(id: string) {
    try {

      const { privateKey, publicKey } = this._tokenRepo.CreateKeysPair();
      const { accessToken, refreshToken } = this._tokenRepo.CreateTokens(id, privateKey);
      await this._tokenRepo.SaveTokens(id, publicKey, refreshToken);
      const proccessACT = this.SplitToken(accessToken)
      const proccessedRFT = this.SplitToken(refreshToken)
      return { access: proccessACT, refresh: proccessedRFT }
    } catch (error) {
      console.log(error);
    }
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
        RabbitMQClient.messageProduce("user-queue", {
          type: "create-user-avatar",
          payload: {
            id: dto.userId,
            avatar: encodeURIComponent("https://d3lugnp3e3fusw.cloudfront.net/143086968_2856368904622192_1959732218791162458_n.png"),
            bio: ""
          }
        })
        RabbitMQClient.messageProduce('chat-queue', {
          type: 'add-user',
          payload: {
            userId: dto.userId,
            fullName: dto.fullName,
          },
        });
        const login = await this.PasswordLogin({ email: dto.email, password: dto.password })
        return login;
      } catch (error) {
        logger.error(error['message']);
        throw new InvalidCredentials()
      }
    }
  }
  async LoginOptions(email: string) {
    const opts = {
      password: true,
    }
    try {
      const res = (await RabbitMQClient.clientProduce("user-queue", {
        type: 'get-user-by-email',
        payload: { email: email },
      })) as IMessageResponse;
      if (res.code !== 1200) {
        return {
          opts
        };
      }
      const optionsKey = await this._authRepo.LoginOptions(res.payload["userId"])
      if (!optionsKey || optionsKey.devices.length === 0) {
        return {
          opts
        }
      }
      return { opts: { ...opts, passkey: true } };

    } catch (error) {
      logger.error(error);
      return { opts }
    }
  }
  async WebAuthnRegistrationOptions(email: string) {
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
    const options: GenerateRegistrationOptionsOpts = {
      rpName: 'Chat App',
      rpID: config["COOKIES_DOMAIN"],
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
      const res = (await RabbitMQClient.clientProduce("user-queue", {
        type: 'get-user-by-email',
        payload: {
          email: credential['user']['email']
        },
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
        expectedOrigin: ['https://' + config['ORIGIN'], 'https://www.' + config['ORIGIN'], config['ORIGIN']],
        expectedRPID: config['COOKIES_DOMAIN'],
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
            createdAt: Date.now().toString()
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
              createdAt: Date.now().toString()
            };
            await this._authRepo.AddDevice(auth.id, userId, newDevice);
            console.log(newDevice);
          }
        }
        return { id: btoa(String.fromCharCode(...Array.from(credentialID))) };
      }
    } catch (error) {
      console.log(error);
      return { ok: 'not ok' };
    }
  }
  async WebAuthnLoginOptions(email: string) {
    try {
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
        rpID: config['COOKIES_DOMAIN'],
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
    const res = (await RabbitMQClient.clientProduce("user-queue", {
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
      throw new InvalidCredentials()
    }
    let verification: VerifiedAuthenticationResponse;
    try {
      const options: VerifyAuthenticationResponseOpts = {
        response: data,
        expectedChallenge: `${expectedChallenge}`,
        expectedOrigin: ['https://' + config['ORIGIN'], 'https://www.' + config['ORIGIN'], config['ORIGIN']],
        expectedRPID: config['COOKIES_DOMAIN'],
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
    if (verified) {
      await this._authRepo.UpdatePasskeyCounter(authn.id, user.id, data['rawId'], authenticationInfo.newCounter);
      const tokens = await this.CreateAndSaveTokens(res.payload["userId"])
      return { userId, ...tokens }
    } else {
      throw new WrongCredentials()
    }
  }
}

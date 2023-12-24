import { id, inject, injectable } from 'inversify';

import { Prisma, PrismaClient } from '@prisma/client';

import { TYPES } from '../@types';
import { AuthCreateDto, AuthnPasswordDto, IAddGoogleDto, OAuthType } from '@v1';
import { Options, decode, encode } from '../../../utils';
import { InternalError, NotFound } from '../../../libs/base-exception';
import { AuthnOptions, User } from '../../../config';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import base64url from 'base64url';

export interface IAuthRepository {
  AddPassword(dto: AuthnPasswordDto): Promise<void>;
  CreateOne(dto: AuthCreateDto): Promise<void>;
  PasswordLogin(dto: { id: string; password: string }): Promise<any>;
  LoginOptions(id: string): Promise<any>;
  AddGoogle(dto: IAddGoogleDto): Promise<void>;
  FindOneWithKeyValue(userId: string, value: OAuthType, type: 'oauth' | 'otp'): Promise<AuthnOptions>;
  FindOneByUserId(userId: string, type: 'oauth' | 'passkey' | 'password' | 'otp'): Promise<AuthnOptions>;
  AddChallenge(userId: string, challenge: string): Promise<void>;
  GetUserById(userId: string): Promise<User>;
  CreateDevice(userId: string, device: any): Promise<void>;
  AddDevice(id: string, userId: string, device: any): Promise<void>;
  FindPasskeys(id: string): Promise<Prisma.JsonValue>;
  UpdatePasskeyCounter(id: string, userId: string, raw: string, counter: number): Promise<void>;
  FindPasswordByUserId(id: string): Promise<string>;
  TestCnt(): Promise<void>
}
@injectable()
export class AuthRepository implements IAuthRepository {
  constructor(
    @inject(TYPES.Prisma)
    private readonly _db: PrismaClient
  ) { }
  async TestCnt(): Promise<void> {
    await this._db.user.count()
  }
  async FindPasswordByUserId(id: string): Promise<string> {
    const auth = await this._db.authnOptions.findFirst({
      where: {
        option: 'password',
        userId: id,
      },
    });
    if (!auth) {
      throw new NotFound();
    }
    const { value } = auth.key as Prisma.JsonObject;
    return value as string;
  }
  async CreateDevice(userId: string, device: any): Promise<any> {
    const execute: string | any[] = [];
    const json = {
      devices: [device],
      webauthn: true,
    };
    execute.push(
      this._db.authnOptions.create({
        data: {
          option: 'passkey',
          userId: userId,
          key: json,
        },
      }),
    );
    if (execute.length > 0) {
      await this._db.$transaction(execute);
    }
  }

  async AddDevice(id: string, userId: string, device: any): Promise<any> {
    const execute: string | any[] = [];
    const data = await this._db.authnOptions.findFirst({
      where: {
        userId: userId,
        option: 'passkey',
      },
    });
    console.log('check data:::', data);
    const json = {
      ...(data['key'] as []),
      devices: [...(data['key']['devices'] as []), device],
      webauthn: true,
    };
    execute.push(
      this._db.authnOptions.update({
        where: {
          id: id,
        },
        data: {
          key: json,
        },
      }),
    );
    if (execute.length > 0) {
      await this._db.$transaction(execute);
    }
  }
  public FindOneByUserId = async (userId: string, type: 'oauth' | 'passkey' | 'password' | 'otp') => {
    const option = await this._db.authnOptions.findFirst({
      where: {
        userId: userId,
        option: type,
      },
    });
    return option ?? null;
  };
  async AddGoogle(dto: IAddGoogleDto): Promise<any> {
    const execute: string | any[] = [];
    try {
      const option = await this.FindOneByUserId(dto.id, 'oauth');
      console.log(option);

      if (!option) {
        const json = {
          value: [
            {
              google: dto.email,
            },
          ],
          federated: [{ google: dto.aud || process.env.GOOGLE_CLIENT_ID }],
        } as Prisma.JsonObject;
        execute.push(
          this._db.authnOptions.create({
            data: {
              userId: dto.id,
              option: 'oauth',
              key: json,
            },
          }),
        );
      } else {
        if (option.key['value'] && !(await this.FindOneWithKeyValue(dto.id, 'google', 'oauth'))) {
          const key = option.key as Prisma.JsonObject;
          if (key['value'] && key['federated']) {
            const value = key['value'] as Prisma.JsonArray;
            const federated = key['federated'] as Prisma.JsonArray;
            const json = {
              ...key,
              value: [...value, { google: dto.email }],
              federated: [...federated, { google: dto.aud || process.env.GOOGLE_CLIENT_ID }],
            } as Prisma.JsonObject;
            const whereClause = Prisma.validator<Prisma.AuthnOptionsWhereInput>()({
              id: option.id,
            });
            const updateClause = Prisma.validator<Prisma.AuthnOptionsUpdateInput>()({
              key: json,
            });
            execute.push(
              this._db.authnOptions.update({
                where: whereClause,
                data: updateClause,
              }),
            );
          }
        }
      }
      if (execute.length > 0) {
        await this._db.$transaction(execute);
      }
    } catch (error) {
      console.log(error);
      throw new InternalError();
    }
  }
  async FindOneWithKeyValue(userId: string, value: OAuthType, type: 'oauth' | 'otp') {
    const oAuth = await this._db.authnOptions.findFirst({
      where: {
        userId: userId,
        option: type,
      },
    });
    console.log(oAuth);
    return oAuth ?? null;
  }
  async LoginOptions(id: string): Promise<any> {
    const options = await this._db.authnOptions.findMany({
      where: {
        userId: id,
        NOT: {
          option: 'password',
        },
      },
    });
    return Options(options);
  }
  async PasswordLogin(dto: { id: string; password: string }): Promise<any> {
    try {
      const auth = await this._db.authnOptions.findFirst({
        where: {
          option: 'password',
          userId: dto.id,
        },
      });
      if (!auth) {
        return { message: 'wrong pssword' };
      }
      const { value } = auth.key as Prisma.JsonObject;
      const isSimilar = await decode(dto.password, value as string);
      if (isSimilar) {
        // const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        //   modulusLength: 2048,
        //   publicKeyEncoding: {
        //     type: 'pkcs1',
        //     format: 'pem',
        //   },
        //   privateKeyEncoding: {
        //     type: 'pkcs1',
        //     format: 'pem',
        //   },
        // });
        // const token = jwt.sign(auth.userId, privateKey, { algorithm: 'RS256' });
        return { ok: 'ok' };
      }
      return { message: 'wrong password' };
    } catch (error) {
      console.log(error);
      return { err: 'err' };
    }
  }

  async CreateOne(dto: AuthCreateDto): Promise<any> {
    const execute: string | any[] = [];
    execute.push(
      this._db.user.create({
        data: dto
      }),
    );
    await this._db.$transaction(execute);
  }
  async AddPassword(dto: AuthnPasswordDto) {
    const execute: string | any[] = [];
    const json = {
      value: await encode(dto.pasword),
    } as Prisma.JsonObject;
    execute.push(
      this._db.authnOptions.create({
        data: {
          option: 'password',
          userId: dto.id,
          key: json,
        },
      }),
    );
    await this._db.$transaction(execute);
  }
  async FindPasskeys(userId: string) {
    const passkeys = await this._db.authnOptions.findFirst({
      where: {
        userId: userId,
        option: 'passkey',
      },
    });
    return passkeys.key ?? null;
  }
  async AddChallenge(userId: string, challenge: string): Promise<any> {
    const execute: string | any[] = [];
    execute.push(
      this._db.user.update({
        where: {
          id: userId,
        },
        data: {
          currentChallenge: challenge,
        },
      }),
    );
    if (execute.length > 0) {
      await this._db.$transaction(execute);
    }
  }
  async GetUserById(userId: string): Promise<any> {
    const user = await this._db.user.findFirst({
      where: {
        id: userId,
      },
    });
    return user ?? null;
  }
  async UpdatePasskeyCounter(id: string, userId: string, raw: string, counter: number) {
    try {
      const bodyCredIDBuffer = base64url.toBuffer(raw);
      const passkeys = await this.FindPasskeys(userId);
      if (!passkeys) {
        throw new NotFound();
      }
      const execute: string | any[] = [];
      (passkeys['devices'] as []).forEach((device: any) => {
        if (Buffer.from(device['credentialID']).equals(bodyCredIDBuffer)) {
          device['counter'] = counter;
        }
      });
      const whereClause = Prisma.validator<Prisma.AuthnOptionsWhereInput>()({
        id: id,
      });
      const dataClause = Prisma.validator<Prisma.AuthnOptionsUpdateInput>()({
        key: passkeys,
      });
      execute.push(
        this._db.authnOptions.update({
          where: whereClause,
          data: dataClause,
        }),
      );
      if (execute.length > 0) {
        await this._db.$transaction(execute);
      }
    } catch (error) {
      console.log(error);
      throw new InternalError();
    }
  }
}

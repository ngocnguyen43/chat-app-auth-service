import { inject, injectable } from 'inversify';

import { Prisma, PrismaClient } from '@prisma/client';

import { PasskeysValuesType, TYPES } from '../@types';
import { AuthCreateDto, AuthnPasswordDto, IAddGoogleDto, OAuthType } from '@v1';
import { Options, arraysEqual, decode, encode } from '../../../utils';
import { InternalError, NotFound, WrongPassword } from '../../../libs/base-exception';
import { AuthnOptions, User } from '../../../config';
import base64url from 'base64url';


export interface IAuthRepository {
  AddPassword(dto: AuthnPasswordDto): Promise<void>;
  CreateOne(dto: AuthCreateDto): Promise<void>;
  PasswordLogin(dto: { id: string; password: string }): Promise<any>;
  LoginOptions(id: string): Promise<PasskeysValuesType | null>;
  AddGoogle(dto: IAddGoogleDto): Promise<void>;
  FindOneWithKeyValue(userId: string, value: OAuthType, type: 'oauth' | 'otp'): Promise<AuthnOptions>;
  FindOneByUserId(userId: string, type: 'oauth' | 'passkey' | 'password' | 'otp'): Promise<AuthnOptions>;
  AddChallenge(userId: string, challenge: string): Promise<void>;
  GetUserById(userId: string): Promise<User>;
  CreateDevice(userId: string, device: any): Promise<void>;
  AddDevice(id: string, userId: string, device: any): Promise<void>;
  FindPasskeys(id: string): Promise<PasskeysValuesType | null>;
  UpdatePasskeyCounter(id: string, userId: string, raw: string, counter: number): Promise<void>;
  FindPasswordByUserId(id: string): Promise<string>;
  TestCnt(): Promise<void>
  AddOauth2(id: string, provider: string): Promise<void>
  CheckLoginBefore(id: string, provider: string): Promise<{ provider: string, isLoginBefore: boolean }>
  UpdateStatusLogin(id: string, provider: string): Promise<void>
  DeleteUser(id: string): Promise<void>
  DeletePasskeys(base64id: string, userId: string): Promise<void>
  UpdatePassword(password: string, userId: string): Promise<void>
  Create2FA(id: string, userId: string, secret: string): Promise<void>
  Update2FA(id: string, secret: string, enable: boolean): Promise<void>
  FindOneFA(userId: string): Promise<string | null>
  FindOneFAWithSecret(id: string): Promise<{ secret: string, enable: boolean } | null>
  Delete2FA(id: string): Promise<void>
}
@injectable()
export class AuthRepository implements IAuthRepository {
  constructor(
    @inject(TYPES.Prisma)
    private readonly _db: PrismaClient
  ) { }
  async Delete2FA(id: string): Promise<void> {
    const execute: string | any[] = [];
    execute.push(this._db.authnOptions.delete({
      where: {
        id,
      },

    }))
    await this._db.$transaction(execute)
  }
  async FindOneFAWithSecret(id: string): Promise<{ secret: string; enable: boolean; } | null> {
    const exist = await this._db.authnOptions.findFirst({
      where: {
        AND: {
          userId: id,
          option: "mfa"
        }
      }
    })
    const key = exist ? exist.key as { secret: string, enable: boolean } : null
    return key ?? null
  }
  async Update2FA(id: string, secret: string, enable: boolean): Promise<void> {
    const execute: string | any[] = [];
    const json = {
      secret,
      enable
    }
    execute.push(this._db.authnOptions.update({
      where: {
        id,
      },
      data: {
        key: json
      },

    }))
    await this._db.$transaction(execute)
  }
  async FindOneFA(userId: string): Promise<string | null> {
    try {
      const exist = await this._db.authnOptions.findFirst({
        where: {
          AND: {
            userId,
            option: "mfa"
          }
        }
      })
      if (!exist) {
        return null
      }
      const key = exist ? exist.key as { secret: string, enable: boolean } : null
      if (!key) {
        return null
      }
      return exist.id

    } catch (error) {
      console.log(error);
      return null
    }
  }
  async Create2FA(id: string, userId: string, secret: string): Promise<void> {
    const execute: string | any[] = [];
    const json = {
      secret,
      enable: false
    }
    execute.push(this._db.authnOptions.create({
      data: {
        id,
        userId,
        option: "mfa",
        key: json

      },

    }))
    await this._db.$transaction(execute)
  }
  async FindExistPassword(userId: string): Promise<any> {
    const exist = await this._db.authnOptions.findFirstOrThrow({
      where: {
        userId,
        option: "password"
      }
    })
    return exist ?? null
  }
  async UpdatePassword(password: string, id: string): Promise<void> {
    const execute: string | any[] = [];
    const existPassword = await this.FindExistPassword(id)
    if (existPassword) {
      const json = {
        value: await encode(password),
      } as Prisma.JsonObject;
      execute.push(
        this._db.authnOptions.update({
          where: {
            id: existPassword["id"]
          },
          data: {
            key: json,
          },
        }),
      );
      await this._db.$transaction(execute);
    }
  }
  async DeletePasskeys(base64id: string, userId: string): Promise<void> {
    const passkeys = await this._db.authnOptions.findFirst({
      where: {
        userId,
        option: 'passkey',
      },
    });

    const key = passkeys.key as PasskeysValuesType
    if (key.devices.length > 0) {
      const binaryString = atob(base64id)
      const arrayChars = Array.from(binaryString, c => c.charCodeAt(0))
      const after = key.devices.filter(i => !arraysEqual(arrayChars, i.credentialID))
      console.log(after);
      if (after.length >= 0) {
        const execute: string | any[] = [];
        const json = {
          ...(passkeys.key as []),
          devices: [...after],
          webauthn: true,
        };
        execute.push(
          this._db.authnOptions.update({
            where: {
              id: passkeys.id
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

    }
  }
  async DeleteUser(id: string): Promise<void> {
    const execute: string | any[] = [];
    execute.push(
      this._db.user.delete({
        where: {
          id
        }
      }),
    );
    await this._db.$transaction(execute);

  }
  async UpdateStatusLogin(id: string, provider: string): Promise<void> {
    const otps = await this._db.authnOptions.findFirst({
      where: {
        userId: id,
        key: {
          path: '$.provider',
          equals: provider
        }
      }
    })
    const json = {
      // ...(otps.key as Prisma.JsonObject),
      provider: provider,
      isLoginBefore: true
    };
    console.log(otps);

    const execute: string | any[] = [];
    execute.push(
      this._db.authnOptions.update({
        where: {
          id: otps.id
        },
        data: {
          key: json
        }
      }),
    );
    await this._db.$transaction(execute);

  }
  async CheckLoginBefore(id: string, provider: string): Promise<any> {
    const otps = await this._db.authnOptions.findFirst({
      where: {
        userId: id,
        key: {
          path: '$.provider',
          equals: provider
        }
      }
    })
    return otps.key ?? null
  }
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
      throw new WrongPassword();
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
    const options = await this._db.authnOptions.findFirst({
      where: {
        AND: {
          userId: id,
          option: 'passkey',
        }
      },
    });
    return options ? options.key as PasskeysValuesType : null
  }
  async PasswordLogin(dto: { id: string; password: string }): Promise<any> {
    try {
      const auth = await this._db.authnOptions.findFirstOrThrow({
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
  async AddOauth2(userId: string, provider: string) {
    const execute: string | any[] = [];
    const json = {
      provider,
      isLoginBefore: false
    } as Prisma.JsonObject;
    execute.push(
      this._db.authnOptions.create({
        data: {
          option: "oauth",
          userId: userId,
          key: json,
        },
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
    return passkeys.key as PasskeysValuesType ?? null;
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

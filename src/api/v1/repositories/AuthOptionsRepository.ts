import { prisma, Prisma } from '../config';
import { decode, Options } from '../utils';
import { encode } from '../utils';
import { Unexpected } from './exceptions';
type OAuthType = 'google' | 'facebook' | 'github';
export default class AuthOptionsRepository {
  public static async AddPassword(userId: string, password: string) {
    const execute: string | any[] = [];
    const json = {
      value: await encode(password),
    } as Prisma.JsonObject;
    execute.push(
      prisma.authnOptions.create({
        data: {
          option: 'password',
          userId: userId,
          key: json,
        },
      }),
    );
    await prisma.$transaction(execute);
  }
  public static async FindOneWithKeyValue(userId: string, value: OAuthType, type: 'oauth' | 'otp') {
    const oAuth = await prisma.authnOptions.findFirst({
      where: {
        userId: userId,
        option: type,
      },
    });
    console.log(oAuth);
    return oAuth ?? null;
  }
  public static FindOneByUserId = async (userId: string, type: 'oauth' | 'passkey' | 'password' | 'otp') => {
    const option = await prisma.authnOptions.findFirst({
      where: {
        userId: userId,
        option: type,
      },
    });
    return option ?? null;
  };
  public static async AddEmail(userId: string, email: string, aud?: string) {
    const execute: string | any[] = [];
    try {
      const option = await this.FindOneByUserId(userId, 'oauth');
      console.log(option);

      if (!option) {
        const json = {
          value: [
            {
              google: email,
            },
          ],
          federated: [{ google: aud || process.env.GOOGLE_CLIENT_ID }],
        } as Prisma.JsonObject;
        execute.push(
          prisma.authnOptions.create({
            data: {
              userId: userId,
              option: 'oauth',
              key: json,
            },
          }),
        );
      } else {
        if (option.key['value'] && !this.FindOneWithKeyValue(userId, 'google', 'oauth')) {
          const key = option.key as Prisma.JsonObject;
          if (key['value'] && key['federated']) {
            const value = key['value'] as Prisma.JsonArray;
            const federated = key['federated'] as Prisma.JsonArray;
            const json = {
              ...key,
              value: [...value, { google: email }],
              federated: [...federated, { google: aud || process.env.GOOGLE_CLIENT_ID }],
            } as Prisma.JsonObject;
            const whereClause = Prisma.validator<Prisma.AuthnOptionsWhereInput>()({
              id: option.id,
            });
            const updateClause = Prisma.validator<Prisma.AuthnOptionsUpdateInput>()({
              key: json,
            });
            execute.push(
              prisma.authnOptions.update({
                where: whereClause,
                data: updateClause,
              }),
            );
          }
        }
      }
      if (execute.length > 0) {
        await prisma.$transaction(execute);
      }
    } catch (error) {
      console.log(error);
      throw new Unexpected();
    }
  }
  public static LoginOptions = async (id: string | null) => {
    if (!id) {
      return { password: true };
    }
    const options = await prisma.authnOptions.findMany({
      where: {
        userId: id,
        NOT: {
          option: 'password',
        },
      },
    });
    return Options(options);
  };
  public static LoginPassword = async (id: string, password: string) => {
    if (!id) {
      return { ok: 'not ok' };
    }
    try {
      const authn = await prisma.authnOptions.findFirst({
        where: {
          userId: id,
          option: 'password',
        },
      });
      if (!authn) {
        return { ok: 'not ok' };
      }
      const { value } = authn.key as Prisma.JsonObject;
      const isSimilar = await decode(password, value as string);
      if (isSimilar) {
        return { ok: 'ok' };
      }
      return { ok: 'not ok' };
    } catch (error) {
      console.log(error);
      throw new Unexpected();
    }
  };
  public static AddChallenge = async (userId: string, challenge: string) => {
    try {
      const execute: string | any[] = [];
      execute.push(
        prisma.user.update({
          where: {
            id: userId,
          },
          data: {
            currentChallenge: challenge,
          },
        }),
      );
      if (execute.length > 0) {
        await prisma.$transaction(execute);
      }
    } catch (error) {
      console.log(error);
      throw new Unexpected();
    }
  };
  public static AddDevice = async (id: string, userId: string, device: any) => {
    try {
      const execute: string | any[] = [];
      const data =
        (await prisma.authnOptions.findFirst({
          where: {
            userId: userId,
            option: 'passkey',
          },
        })) ?? {};
      const json = {
        ...data,
        devices: [...data['devices'], device],
        webauthn: true,
      };
      execute.push(
        prisma.authnOptions.update({
          where: {
            id: id,
          },
          data: {
            key: json,
          },
        }),
      );
      if (execute.length > 0) {
        await prisma.$transaction(execute);
      }
    } catch (error) {
      console.log(error);
      throw new Unexpected();
    }
  };
  public static CreateDevice = async (userId: string, device: any) => {
    try {
      const execute: string | any[] = [];
      const json = {
        devices: [device],
        webauthn: true,
      };
      execute.push(
        prisma.authnOptions.create({
          data: {
            option: 'passkey',
            userId: userId,
            key: json,
          },
        }),
      );
      if (execute.length > 0) {
        await prisma.$transaction(execute);
      }
    } catch (error) {
      console.log(error);
      throw new Unexpected();
    }
  };
}

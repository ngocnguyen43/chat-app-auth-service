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
  private static async ContainsValue(value: OAuthType) {
    const oAuth = prisma.authnOptions.findMany({
      where: {
        key: {
          path: '$[*].value',
          array_contains: value,
        },
      },
    });
    return oAuth ?? null;
  }
  public static async FindOneByUserId(userId: string) {
    const option = await prisma.authnOptions.findFirst({
      where: {
        userId: userId,
        option: 'oauth',
      },
    });
    return option ?? null;
  }
  public static async AddEmail(userId: string, email: string) {
    const execute: string | any[] = [];
    try {
      const option = await this.FindOneByUserId(userId);
      console.log(option);

      if (!option) {
        const json = {
          value: [
            {
              google: email,
            },
          ],
          federated: [{ google: process.env.GOOGLE_CLIENT_ID }],
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
        if (option.key['value'] && !this.ContainsValue('google')) {
          const key = option.key as Prisma.JsonObject;
          if (key['value'] && key['federated']) {
            const value = key['value'] as Prisma.JsonArray;
            const federated = key['federated'] as Prisma.JsonArray;
            const json = {
              ...key,
              value: [...value, { google: email }],
              federated: [...federated, { gooel: process.env.GOOGLE_CLIENT_ID }],
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
}

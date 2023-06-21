import { prisma, Prisma } from '../config';
import { encode } from '../utils/decode';
import { Unexpected } from './exceptions';
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
  public static async FindOneByUserId(userId: string) {
    const option = await prisma.authnOptions.findFirst({
      where: {
        id: userId,
        option: 'oauth',
      },
    });
    return option ?? null;
  }
  public static async AddEmail(userId: string, email: string) {
    const execute: string | any[] = [];
    try {
      const option = await this.FindOneByUserId(userId);
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
            option: 'oauth',
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
      await prisma.$transaction(execute);
    } catch (error) {
      console.log(error);
      throw new Unexpected();
    }
  }
}

import { prisma, Prisma } from '../config';
import { encode } from '../utils/decode';
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
}

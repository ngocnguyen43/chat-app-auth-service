import { User } from '@prisma/client';
import { prisma, Prisma } from '../config';
import { RegistrationDto } from '@v1/interface';
export default class UserRepository {
  public static async findOneById(id: string) {
    const user = await prisma.user.findFirst({
      where: {
        id: id,
      },
    });
    return user ?? null;
  }
  public static async findOneByEmail(email: string) {
    const user = await prisma.user.findFirst({
      where: {
        email: email,
      },
    });
    return user ?? null;
  }
  public static createOne = async (user: RegistrationDto): Promise<User> => {
    const execute: string | any[] = [];
    execute.push(
      prisma.user.create({
        data: {
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
        },
      }),
    );
    const [res] = await prisma.$transaction(execute, {
      isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
    });
    return res;
  };
}

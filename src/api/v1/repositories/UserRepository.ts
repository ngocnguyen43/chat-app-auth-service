import { RegistrationDto, userGoogleLoginDto } from '@v1/interface';
import { prisma, Prisma, User } from '../config';
import { UserAlreadyExists } from './exceptions';
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
    const userFound = await this.findOneByEmail(user.email);
    if (userFound) throw new UserAlreadyExists();
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
  public static createOneFromGoogle = async (user: userGoogleLoginDto): Promise<User> => {
    const execute: string | any[] = [];
    const userFound = await this.findOneByEmail(user.email);
    console.log(userFound);

    if (!userFound) {
      execute.push(
        prisma.user.create({
          data: {
            email: user.email,
            firstName: user.family_name,
            lastName: user.given_name,
          },
        }),
      );
      const [res] = await prisma.$transaction(execute, {
        isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
      });
      return res;
    }
    return userFound;
  };
}

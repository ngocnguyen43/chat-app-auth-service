import prisma from '../config';
import { RegistrationDto } from '@v1/interface';

export default class UserRepository {
  public static async findOneById(id: string) {
    const user = await prisma.users.findFirst({
      where: {
        id: id,
      },
    });
    return user ?? null;
  }
  public static async findOneByEmail(email: string) {
    const user = await prisma.users.findFirst({
      where: {
        email: email,
      },
    });
    return user ?? null;
  }
  public static async createOne(user: RegistrationDto) {
    await prisma.users.create({
      data: {
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
      },
    });
  }
}

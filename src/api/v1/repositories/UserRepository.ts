import prisma from '../config';

export class userRepository {
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
}

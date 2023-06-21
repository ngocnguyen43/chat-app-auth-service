import { PrismaClient, Prisma, User } from '@prisma/client';
const prisma = new PrismaClient();
export { prisma, Prisma, User };

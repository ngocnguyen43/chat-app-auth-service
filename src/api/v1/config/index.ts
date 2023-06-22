import { PrismaClient, Prisma, User, AuthnOptions } from '@prisma/client';
const prisma = new PrismaClient();
export { prisma, Prisma, User, AuthnOptions };

import { PrismaClient, Prisma, User, AuthnOptions } from '@prisma/client';
import { config } from '../../../config';
const prisma = new PrismaClient();
export { prisma, Prisma, User, AuthnOptions, config };

import { Express } from 'express';
declare namespace NodeJS {
  export interface global {
    abc: string;
  }
}
declare global {
  namespace Express {
    export interface Request {
      accessToken: string;
      refreshToken: string;
      isAccessTokenExpire: boolean;
      userCredentials:
      {
        id: string;
        userId: string;
        publicKey: string;
        refreshToken: string;
        refreshTokenUsed: Prisma.JsonValue;
        updatedAt: string;

      };
      userId: string
    }
  }
}


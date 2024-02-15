import { inject, injectable } from 'inversify';
import { TYPES } from '../@types';
import { Prisma, PrismaClient, Token } from '@prisma/client';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

type CreateKeys = {
  publicKey: string;
  privateKey: string;
};
type CreateTokens = {
  accessToken: string;
  refreshToken: string;
};
export interface ITokenRepository {
  CreateTokens(data: string, privateKey: string): CreateTokens;
  FindTokensByUserId(id: string): Promise<Token | null>;
  UpdateKeys(userId: string, refreshToken: string): Promise<CreateKeys>;
  CreateKeysPair(): CreateKeys;
  SaveTokens(id: string, publicKey: string, refreshToken: string): Promise<void>;
  ClearToken(id: string): Promise<void>;
  GetPublicKeyFromId(id: string): Promise<string | null>;
  ClearRefreshTokensUsed(id: string): Promise<void>
}
@injectable()
export class TokenRepository implements ITokenRepository {
  constructor(
    @inject(TYPES.Prisma)
    private readonly _db: PrismaClient,
  ) { }
  async ClearRefreshTokensUsed(id: string): Promise<void> {
    const execute: string | any[] = [];

    execute.push(
      this._db.token.update({
        data: {
          refreshTokenUsed: [],
        },
        where: {
          userId: id,
        },
      }),
    );
    await this._db.$transaction(execute);
  }
  async GetPublicKeyFromId(id: string): Promise<string | null> {
    const { publicKey } = await this._db.token.findUnique({
      where: {
        userId: id,
      },
      select: {
        publicKey: true,
      },
    });
    return publicKey ?? null;
  }
  async ClearToken(id: string): Promise<void> {
    const execute: string | any[] = [];
    const existedToken = await this.FindTokensByUserId(id);


    const refreshTokenUsed = existedToken.refreshTokenUsed as Prisma.JsonArray | [];
    const refreshToken = existedToken.refreshToken;
    if (refreshToken.length > 0) {
      execute.push(
        this._db.token.update({
          data: {
            publicKey: '',
            refreshToken: '',
            refreshTokenUsed: [...refreshTokenUsed, refreshToken],
          },
          where: {
            userId: id,
          },
        }),
      );
      await this._db.$transaction(execute);
    }
  }
  async SaveTokens(id: string, publicKey: string, refreshToken: string): Promise<void> {
    const execute: string | any[] = [];
    const existToken = await this.FindTokensByUserId(id);
    const unixTimestamp = Date.now().toString()
    if (!existToken) {
      execute.push(
        this._db.token.create({
          data: {
            publicKey: publicKey,
            userId: id,
            refreshToken: refreshToken,
            refreshTokenUsed: [],
            updatedAt: unixTimestamp
          },
        }),
      );
    } else {
      const refreshTokenUsed = existToken.refreshTokenUsed as Prisma.JsonArray;
      const oldRefreshToken = existToken.refreshToken;
      execute.push(
        this._db.token.update({
          data: {
            publicKey: publicKey,
            refreshToken: refreshToken,
            refreshTokenUsed: [...refreshTokenUsed, oldRefreshToken],
          },
          where: {
            userId: id,
          },
        }),
      );
    }
    await this._db.$transaction(execute);
  }
  CreateTokens(data: string, privateKey: string): CreateTokens {
    const accessToken = jwt.sign({
      sub: data
    }, privateKey, {
      algorithm: 'RS256',
      expiresIn: '30d',
    });
    const refreshToken = jwt.sign({
      sub: data
    }, privateKey, {
      algorithm: 'RS256',
      expiresIn: '90d',
    });
    return { accessToken, refreshToken };
  }
  CreateKeysPair(): CreateKeys {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'pkcs1',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs1',
        format: 'pem',
      },
    });
    return { publicKey, privateKey };
  }
  async FindTokensByUserId(id: string): Promise<Token | null> {
    const tokens = await this._db.token.findUnique({
      where: {
        userId: id,
      },
    });
    return tokens ?? null;
  }
  async UpdateKeys(userId: string, refreshToken: string): Promise<CreateKeys> {
    const execute: string | any[] = [];
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'pkcs1',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs1',
        format: 'pem',
      },
    });
    const token = await this._db.token.findUnique({ where: { userId: userId } });
    const refreshTokenUsed = token.refreshTokenUsed as Prisma.JsonArray;
    refreshTokenUsed.push(refreshToken);
    const unixTimestamp = Date.now().toString()
    execute.push(
      this._db.token.update({
        data: {
          publicKey: publicKey,
          refreshTokenUsed: refreshTokenUsed,
          updatedAt: unixTimestamp
        },
        where: {
          userId: userId,
        },
      }),
    );
    await this._db.$transaction(execute);
    return { publicKey, privateKey };
  }
}

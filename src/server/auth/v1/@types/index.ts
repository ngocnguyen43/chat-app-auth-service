const TYPES = {
  Prisma: Symbol.for('Prisma'),
  Lodash: Symbol.for('Lodash'),
  AuthService: Symbol.for('AuthService'),
  AuthRepository: Symbol.for('AuthRepository'),
  AuthController: Symbol.for('AuthController'),
  TokenRepository: Symbol.for('TokenRepository'),
  Middleware: Symbol.for('middleware'),
  MessageExecute: Symbol.for('MessageExecute'),
};
export { TYPES };
export interface IEnvironment {
  environment?: string;
  httpPort?: number;
  httpsPort?: number;
  allowHttp?: boolean;
  keyFile?: string;
  certFile?: string;
  url?: string;
  clientUrl?: string;
  useInMemoryDb?: boolean;
  connectionString?: string;
  encryptionKey?: string;
  facebookClientId?: string;
  facebookClientSecret?: string;
  githubClientId?: string;
  githubClientSecret?: string;
  googleClientId?: string;
  googleClientSecret?: string;
  resetPassTokenExpiration?: number;
  useLocalEmail?: boolean;
  localEmailPath?: string;
  emailFrom?: string;
  sendGridApiKey?: string;
  sendGridTemplates?: { [key: string]: string };
  jwt?: {
    tokenExpiration?: number;
    audiences?: string[];
    audience?: string;
    issuer?: string;
    privateKeyPath?: string;
    publicKeyPath?: string;
  };
}

export type GoogleUserType =
  {
    sub: string,
    name: string,
    given_name: string,
    family_name: string,
    picture: string,
    email: string,
    email_verified: boolean,
    locale: string
  }
export type GithubUserType =
  {
    id: string,
    nodeId: string,
    displayName: string,
    username: string,
    profileUrl: string,
    photos: [
      { value: string }
    ],
    provider: 'github',
  }

export type FacebookUserType =
  {
    id: string,
    username: string | undefined,
    displayName: string,
    name: {
      familyName: string | undefined,
      givenName: string | undefined,
      middleName: string | undefined
    },
    provider: 'facebook',
  }

type UnionKeys<T> = T extends T ? keyof T : never;
type StrictUnionHelper<T, TAll> =
  T extends any
  ? T & Partial<Record<Exclude<UnionKeys<TAll>, keyof T>, never>> : never;

export type StrictUnion<T> = StrictUnionHelper<T, T>
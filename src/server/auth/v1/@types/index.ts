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

export type PasskeysValuesType = {
  devices: {
    counter: number, transports: string[], credentialID: number[], credentialPublicKey: number[], createdAt: string
  }[],
  webauthn: boolean
}
export interface AuthCreateDto {
  id: string;
  createdAt: string;
  updatedAt: string
}
export interface AuthnPasswordDto {
  id: string;
  pasword: string;
}
export interface IPasswordLoginDto {
  email: string;
  password: string;
}
export interface ILoginOptionsDto {
  email: string;
}
export interface IAddGoogleDto {
  id: string;
  email: string;
  aud: string;
}
export type OAuthType = 'google' | 'facebook' | 'github';
export interface IGoogleLoginId {
  credential: string;
}
export interface IWebAuthnRegisterOptions {
  email: string;
}
export interface IWebAuthnLoginOptions {
  email: string;
}
export interface IWebAuthnLoginVerification {
  email: string;
  data: any;
}
export interface IMessageResponse {
  code: number;
  message: string;
  payload: any;
}
export type ValidOption = [object[], string];

export type JwtVerifyType = {
  sub: string,
  iat: number,
  exp: number
}
const TYPES = {
  Prisma: Symbol.for('Prisma'),
  Lodash: Symbol.for('Lodash'),
  AuthService: Symbol.for('AuthService'),
  AuthRepository: Symbol.for('AuthRepository'),
  AuthController: Symbol.for('AuthController'),
  Middleware: Symbol.for('middleware'),
};
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
export { TYPES };

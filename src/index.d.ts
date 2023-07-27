declare namespace NodeJS {
  export interface global {
    abc: string;
  }
}
declare module '@v1' {
  export interface AuthCreateDto {
    id: string;
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
  interface IAddGoogleDto {
    id: string;
    email: string;
    aud: string;
  }
  type OAuthType = 'google' | 'facebook' | 'github';
  interface IGoogleLoginId {
    credential: string;
  }
  interface IWebAuthnRegisterOptions {
    email: string;
  }
  interface IWebAuthnLoginOptions {
    email: string;
  }
  interface IWebAuthnLoginVerification {
    email: string;
    data: any;
  }
}

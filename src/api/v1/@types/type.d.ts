declare module '@v1/interface' {
  export interface LogInDto {
    email: string;
    password: string;
  }
  export interface RegistrationDto {
    firstName: string;
    lastName: string;
    email: string;
    password?: string;
    avatar?: string;
  }
  export interface BaseException {
    getErr(): string;
    getStatusCode(): number;
  }
  export interface Response {
    getMessage(): string;
    getStatus(): number;
  }
  export interface userGoogleLoginDto {
    email: string;
    email_verified: boolean;
    family_name: string;
    given_name: string;
  }
}

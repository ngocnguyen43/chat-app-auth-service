declare module '@v1/interface' {
  interface LogInDto {
    email: string;
    password: string;
  }
  interface RegistrationDto {
    firstName: string;
    lastName: string;
    email: string;
    password?: string;
    avatar?: string;
  }
  interface BaseException {
    getErr(): string;
    getStatusCode(): number;
  }
  interface Response {
    getMessage(): string;
    getStatus(): number;
  }
  interface userGoogleLoginDto {
    email: string;
    email_verified: boolean;
    family_name: string;
    given_name: string;
  }
}

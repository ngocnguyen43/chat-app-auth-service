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
}

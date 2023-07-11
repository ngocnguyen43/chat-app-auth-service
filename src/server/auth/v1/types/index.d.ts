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
}

import { BaseException } from '@v1/interface';

export class UserAlreadyExists implements BaseException {
  constructor(private err: string = 'user already in use', private status_code: number = 404) {}
  getErr(): string {
    return this.err;
  }
  getStatusCode(): number {
    return this.status_code;
  }
}
export class Unexpected implements BaseException {
  constructor(private err = 'unexpected error', private status_code = 400) {}
  getErr(): string {
    return this.err;
  }
  getStatusCode(): number {
    return this.status_code;
  }
}

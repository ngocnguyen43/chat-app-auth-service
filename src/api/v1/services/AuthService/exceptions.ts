import { BaseException } from '@v1/interface';

export class UserAlreadyExists implements BaseException {
  constructor(private err: string = '', private status_code: number = 404) {}
  getErr(): string {
    return this.err;
  }
  getStatusCode(): number {
    return this.status_code;
  }
}

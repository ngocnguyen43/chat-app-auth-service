import { BaseException } from '@v1/interface';

export class InvalidEndPoint implements BaseException {
  constructor(private err = 'endpoint not found', private status = 404) {}
  getErr(): string {
    return this.err;
  }
  getStatusCode(): number {
    return this.status;
  }
}

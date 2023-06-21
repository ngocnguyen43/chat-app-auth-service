import { Response } from '@v1/interface';

export class CREATED implements Response {
  constructor(private message = 'created', private status = 201) {}
  getStatus(): number {
    return this.status;
  }
  getMessage() {
    return this.message;
  }
}

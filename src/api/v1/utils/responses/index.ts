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
export class Authenticated implements Response {
  constructor() {}
  getMessage(): string {
    throw new Error('Method not implemented.');
  }
  getStatus(): number {
    throw new Error('Method not implemented.');
  }
}

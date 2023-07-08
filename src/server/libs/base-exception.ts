import { Reasons, StatusCode } from '../utils';

export class BaseError extends Error {
  constructor(public readonly statusCode: number, public readonly message: string) {
    super();
  }
}
export class NotFound extends BaseError {
  constructor() {
    super(StatusCode.NOT_FOUND, Reasons.NOT_FOUND);
  }
}

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
export class InternalError extends BaseError {
  constructor() {
    super(StatusCode.INTERNAL_SERVER_ERROR, Reasons.INTERNAL_SERVER_ERROR);
  }
}
export class WrongPassword extends BaseError {
  constructor() {
    super(StatusCode.UNAUTHORIZED, 'wrong password');
  }
}

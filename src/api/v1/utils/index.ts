import { AuthnOptions } from '../config';

export { ErrorHandler } from './errorHandler';
export * from './responses';
export { encode } from './encode';
export { decode } from './decode';
export const Options = (arr: AuthnOptions[]) => {
  let obj = {
    password: true,
  };
  arr.forEach((item) => {
    obj[item.option] = true;
  });
  return obj;
};

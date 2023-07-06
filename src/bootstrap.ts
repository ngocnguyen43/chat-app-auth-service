import { Application } from './server/application';
console.clear();

export function boostrap() {
  new Application().setup();
}
boostrap();

import { Application } from './server/application';
console.clear();

export async function boostrap() {
  new Application().setup();
}
boostrap();

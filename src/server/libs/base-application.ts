export abstract class AbstractApplication {
  abstract setup(): Promise<void> | void;
}

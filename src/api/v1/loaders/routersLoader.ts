import { Express } from 'express';

import { AuthRouter } from '../routers';

export default class RouterLoader {
  public static init = (version: string, app: Express) => {
    app.use(`/api/${version}`, AuthRouter);
    return app;
  };
}

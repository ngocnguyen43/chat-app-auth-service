import app from './api/app';
import { config } from './config';
app.listen(config.port, () => console.log(`App is on PORT: ${config.port}`));

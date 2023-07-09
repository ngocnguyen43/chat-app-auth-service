import winston from 'winston';
import { config } from '../config';
import fs from 'fs';
import path from 'path';
const logDir = 'src/server/log'; // directory path you want to set
if (!fs.existsSync(logDir)) {
  // Create the directory if it does not exist
  fs.mkdirSync(logDir);
}
export const logger = winston.createLogger({
  level: 'info',
  // format: winston.format.json(),
  defaultMeta: { service: 'auth-service' },
  transports: [
    //
    // - Write all logs with importance level of `error` or less to `error.log`
    // - Write all logs with importance level of `info` or less to `combined.log`
    //
    new winston.transports.File({ filename: path.join(logDir, '/error.log'), level: 'error' }),
    new winston.transports.File({ filename: path.join(logDir, '/combined.log') }),
  ],
});
// Development Logger
if (config.state != 'production') {
  logger.add(new winston.transports.Console());
}

process.on('unhandledRejection', function (reason, p) {
  logger.warn('system level exceptions at, Possibly Unhandled Rejection at: Promise ', p, ' reason: ', reason);
});

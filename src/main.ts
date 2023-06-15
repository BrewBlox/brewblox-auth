import cors from '@koa/cors';
import axios from 'axios';
import Koa from 'koa';
import session from 'koa-session';
import { get } from 'lodash';
import args from './args';
import { privateAuth, publicAuth } from './auth';
import logger from './logger';

const publicApp = new Koa();
const privateApp = new Koa();

publicApp.use(session(publicApp));
publicApp.use(cors());
publicApp.use(publicAuth.routes());
publicApp.use(publicAuth.allowedMethods());

privateApp.use(session(privateApp));
privateApp.use(cors());
privateApp.use(privateAuth.routes());
privateApp.use(privateAuth.allowedMethods());

axios.interceptors.response.use(
  (response) => response,
  (e) => {
    const resp = get(e, 'response.data', e.message ?? null);
    const err = resp instanceof Object ? JSON.stringify(resp) : resp;
    const url = get(e, 'response.config.url');
    const method = get(e, 'response.config.method');
    const status = get(e, 'response.status');
    const msg = `[HTTP ERROR] method=${method}, url=${url}, status=${status}, response=${err}`;
    return Promise.reject(new Error(msg));
  },
);

logger.info('==========Startup==========');

publicApp.listen(args.publicPort, () => {
  logger.info(`Public app is running at http://0.0.0.0:${args.publicPort}`);
});

privateApp.listen(args.privatePort, () => {
  logger.info(`Private app is running at http://0.0.0.0:${args.privatePort}`);
});

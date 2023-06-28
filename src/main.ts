import { bodyParser } from '@koa/bodyparser';
import cors from '@koa/cors';
import jwt from 'jsonwebtoken';
import Koa from 'koa';
import Router from 'koa-router';
import args from './args';
import logger from './logger';

const jwtSecretKey = 'JWT secret key';
const validity = 1800;

const router = new Router({ prefix: `/${args.name}` });

router.get('/verify', (ctx) => {
  try {
    const authorization = ctx.get('Authorization');
    jwt.verify(authorization, jwtSecretKey);
    ctx.status = 200;
  } catch (e) {
    logger.info(e);
    ctx.throw(401);
  }
});

router.post('/login', (ctx) => {
  const { login, password } = ctx.request.body;
  // TODO: get users from file
  if (login !== 'login' || password !== 'password') {
    ctx.throw(401);
  }

  const token = jwt.sign(
    {
      user: login,
      exp: Math.floor(Date.now() / 1000) + validity,
    },
    jwtSecretKey,
  );

  ctx.status = 200;
  ctx.res.setHeader('Authorization', token);
});

const app = new Koa();
app.use(cors());
app.use(bodyParser());
app.use(router.routes());
app.use(router.allowedMethods());

logger.info('==========Startup==========');

app.listen(args.port, () => {
  logger.info(`App is listening at http://0.0.0.0:${args.port}`);
});

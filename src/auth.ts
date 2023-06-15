import Router from 'koa-router';
import { v4 as uuid } from 'uuid';

const scope = 'openid profile email offline_access';

export const publicAuth = new Router();
export const privateAuth = new Router();

publicAuth.get('/login', (ctx) => {
  if (!ctx.query.redirect_uri) {
    ctx.throw(400, 'missing redirect_uri param');
  }
  const state = uuid();
  ctx.session!.state = state;
  ctx.session!.redirect_uri = ctx.query.redirect_uri;
  const url = [
    `${auth.issuerBaseURL}/authorize?audience=${auth.audience}`,
    `scope=${scope}&response_type=code`,
    `client_id=${auth.clientID}`,
    `redirect_uri=${auth.baseURL}/callback`,
    `state=${state}`,
  ].join('&');
});

publicAuth.get('/callback', (ctx) => {});

publicAuth.get('/userinfos', (ctx) => {});

privateAuth.get('/auth', (ctx) => {});

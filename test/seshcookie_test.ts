import { expect } from 'chai';
import * as cookieParser from 'cookie-parser';
import { CookieAccessInfo } from 'cookiejar';
import * as crypto from 'crypto';
import * as express from 'express';
import * as request from 'supertest';

import * as seshcookie from '../lib/seshcookie';

describe('encryption roundtrips', () => {
  it('works', () => {
    const key = crypto.randomBytes(16);
    const value = 'it was the best of times';
    const ciphertext = seshcookie.encrypt(Buffer.from(value), key);
    expect(ciphertext).not.to.equal(value);
    const plaintext = seshcookie.decrypt(ciphertext, key);
    expect(plaintext).to.equal(value);
  });
});

describe('cookie roundtrips', () => {
  const app = express();

  const config: seshcookie.Options = {
    key: crypto.randomBytes(8).toString('hex'),
    cookieName: 'unittest',
    cookiePath: '/',
    httpOnly: true,
    secure: false,
    maxAgeInSeconds: 60 * 60, // 1 hour
    sameSite: 'strict',
  };

  app.use(cookieParser());
  app.use(seshcookie.seshcookie(config));

  app.get('/set/:name', (req: express.Request, res: express.Response) => {
    req.session.name = req.params.name;
    res.status(200).json({ name: req.params.name });
  });

  app.get('/get', (req: express.Request, res: express.Response) => {
    const name = req.session.name;
    const status = name !== undefined ? 200 : 204;
    res.status(status).json({ name: name });
  });

  app.get('/clear', (req: express.Request, res: express.Response) => {
    req.session = {};
    res.status(200).json({});
  });

  let agent = request.agent(app);

  const name = crypto.randomBytes(8).toString('hex');
  let cookie = '';

  it('sets cookie', (done) => {
    agent
      .get(`/set/${name}`)
      .expect(200)
      .expect('set-cookie', new RegExp(`^${config.cookieName}=`))
      .end((err, res) => {
        if (err) {
          throw err;
        }
        const cookies = res.get('Set-Cookie');
        if (cookies.length !== 1) {
          throw new Error('bad cookie length: ${cookies.length}');
        }
        cookie = cookies[0];
        if (!agent.jar.getCookie(config.cookieName, CookieAccessInfo.All)) {
          throw new Error("I don't seem to understand cookiejar");
        }
        done();
      });
  });

  it('decodes cookie', (done) => {
    agent
      .get(`/get`)
      .expect(200)
      .end((err, res) => {
        expect(res.body.name).equals(name);
        if (err) {
          throw err;
        }
        done();
      });
  });

  it('tolerates bad cookie', (done) => {
    // delete a char from the cookie
    agent.jar.setCookie(cookie.replace(/-./, '-'));
    agent
      .get(`/get`)
      .expect(204)
      .end((err, res) => {
        if (err) {
          throw err;
        }
        done();
      });
  });

  agent = request.agent(app);

  it('clears cookie for empty session', (done) => {
    agent
      .get(`/set/${name}`)
      .expect(200)
      .expect('set-cookie', new RegExp(`^${config.cookieName}=`))
      .end((err, _) => {
        if (err) {
          throw err;
        }

        agent
          .get(`/clear`)
          .expect(200)
          .end((err, res) => {
            if (err) {
              throw err;
            }
            const cookie = agent.jar.getCookie(config.cookieName, CookieAccessInfo.All);
            if (cookie) {
              throw new Error('bad cookie length: ${cookie}');
            }
            done();
          });
      });
  });

  agent = request.agent(app);

  it('sets max age', (done) => {
    agent
      .get(`/set/${name}`)
      .expect(200)
      .expect('set-cookie', new RegExp(`^${config.cookieName}=`))
      .expect('set-cookie', new RegExp(`\\WMax-Age=3600;`))
      .end((err, res) => {
        if (err) {
          throw err;
        }
        const cookies = res.get('Set-Cookie');
        if (cookies.length !== 1) {
          throw new Error('bad cookie length: ${cookies.length}');
        }
        cookie = cookies[0];
        const decodedCookie = agent.jar.getCookie(config.cookieName, CookieAccessInfo.All);
        if (!decodedCookie) {
          throw new Error("I don't seem to understand cookiejar");
        }
        done();
      });
  });

  agent = request.agent(app);

  it('sets same site', (done) => {
    agent.jar.setCookie(cookie.replace(/-./, '-'));
    agent
      .get(`/set/${name}`)
      .expect(200)
      .expect('set-cookie', new RegExp(`^${config.cookieName}=`))
      .expect('set-cookie', new RegExp(`\\WSameSite=Strict(;|$)`))
      .end((err, res) => {
        if (err) {
          throw err;
        }
        const cookies = res.get('Set-Cookie');
        if (cookies.length !== 1) {
          throw new Error('bad cookie length: ${cookies.length}');
        }
        cookie = cookies[0];
        const decodedCookie = agent.jar.getCookie(config.cookieName, CookieAccessInfo.All);
        if (!decodedCookie) {
          throw new Error("I don't seem to understand cookiejar");
        }
        done();
      });
  });
});

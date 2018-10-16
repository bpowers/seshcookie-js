import * as crypto from 'crypto';

import { NextFunction, Request, RequestHandler, Response } from 'express';

const algorithm = 'aes-128-gcm';

const gcmNonceSize = 12;

interface Options {
  key: string; // key used for encrypting + decrypting sessions
  cookieName: string;
  cookiePath: string;
  httpOnly: boolean;
  secure: boolean;
}

function encrypt(plaintext: Buffer, encKey: string): string {
  const nonce = crypto.randomBytes(gcmNonceSize);
  const cipher = crypto.createCipheriv(algorithm, encKey, nonce);

  cipher.setAAD(nonce);
  let ciphertext = cipher.update(plaintext);
  ciphertext = Buffer.concat([ciphertext, cipher.final()]);

  const tag = cipher.getAuthTag();

  return `${nonce.toString('base64')}-${ciphertext.toString(
    'base64',
  )}-${tag.toString('base64')}`;
}

function decrypt(content: string, encKey: string): string {
  const parts = content.split('-');
  if (parts.length !== 3) {
    throw new Error(`expected 3 parts, got ${parts.length}`);
  }
  const [nonce, ciphertext, tag] = parts;
  const cipher = crypto.createDecipheriv(algorithm, encKey, nonce);

  cipher.setAuthTag(Buffer.from(tag, 'base64'));

  cipher.setAAD(Buffer.from(nonce, 'base64'));
  let plaintext = cipher.update(Buffer.from(ciphertext, 'base64'));
  plaintext = Buffer.concat([plaintext, cipher.final()]);

  return plaintext.toString();
}

class SeshCookie {
  key: string;
  cookieName: string;
  cookiePath: string;
  httpOnly: boolean;
  secure: boolean;

  constructor(options: Options) {
    this.key = options.key;
    this.cookieName = options.cookieName;
    this.cookiePath = options.cookiePath;
    this.httpOnly = options.httpOnly;
    this.secure = options.secure;
  }

  handle(req: Request, resp: Response, next: NextFunction): void {
    next();
  }
}

export function seshcookie(options: Options): RequestHandler {
  const seshCookie = new SeshCookie(options);
  return (req: Request, resp: Response, next: NextFunction) => {
    seshCookie.handle(req, resp, next);
  };
}

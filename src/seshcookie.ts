import * as crypto from 'crypto';

import { NextFunction, Request, RequestHandler, Response } from 'express';
import { networkInterfaces } from 'os';

const algorithm = 'aes-128-gcm';

const gcmNonceSize = 12;

interface Options {
  key: string; // key used for encrypting + decrypting sessions
  cookieName: string;
  cookiePath: string;
  httpOnly: boolean;
  secure: boolean;
}

export function encrypt(plaintext: Buffer, encKey: Buffer): string {
  const nonce = crypto.randomBytes(gcmNonceSize);
  const cipher = crypto.createCipheriv(algorithm, encKey, nonce);

  cipher.setAAD(nonce);
  let ciphertext = cipher.update(plaintext);
  ciphertext = Buffer.concat([ciphertext, cipher.final()]);

  const tag = cipher.getAuthTag();

  return `${nonce.toString('base64')}-${ciphertext.toString('base64')}-${tag.toString('base64')}`;
}

export function decrypt(content: string, encKey: Buffer): string {
  const parts = content.split('-');
  if (parts.length !== 3) {
    throw new Error(`expected 3 parts, got ${parts.length}`);
  }

  const [encodedNonce, encodedCiphertext, encodedTag] = parts;
  const nonce = Buffer.from(encodedNonce, 'base64');
  const ciphertext = Buffer.from(encodedCiphertext, 'base64');
  const tag = Buffer.from(encodedTag, 'base64');

  const cipher = crypto.createDecipheriv(algorithm, encKey, nonce);

  cipher.setAAD(nonce);
  cipher.setAuthTag(tag);

  let plaintext = cipher.update(ciphertext);
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

import * as crypto from 'crypto';
import { OutgoingHttpHeaders, OutgoingHttpHeader } from 'http';

import { CookieOptions, NextFunction, Request, RequestHandler, Response } from 'express';

// we use AES128 in Galois Counter Mode; with this GCM instantiation
// the size of the nonce is 12 bytes
const algorithm = 'aes-128-gcm';
const gcmNonceSize = 12;

export interface Options {
  key: string; // key used for encrypting + decrypting sessions
  cookieName: string;
  cookiePath: string;
  httpOnly: boolean;
  secure: boolean;
  maxAgeInSeconds?: number;
  sameSite?: boolean | 'lax' | 'strict' | 'none';
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

// turn a user-provided string into a key of the proper length for our AEAD key
function deriveKey(input: string): Buffer {
  return crypto.createHash('sha256').update(input).digest().slice(0, 16);
}

// using seshcookie extends the Request object with a session field.
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      session: SessionData;
    }

    interface SessionData {
      [key: string]: any;
    }
  }
}

class SeshCookie {
  readonly key: Buffer;
  readonly cookieName: string;
  readonly cookiePath: string;
  readonly httpOnly: boolean;
  readonly secure: boolean;
  readonly maxAge?: number;
  readonly sameSite?: boolean | 'lax' | 'strict' | 'none';

  constructor(options: Options) {
    this.key = deriveKey(options.key);
    this.cookieName = options.cookieName;
    this.cookiePath = options.cookiePath ? options.cookiePath : '/';
    this.httpOnly = options.httpOnly;
    this.secure = options.secure;
    this.maxAge = options.maxAgeInSeconds;
    this.sameSite = options.sameSite;
  }

  private setCookie(res: Response, value: string, expire?: boolean): void {
    const options: CookieOptions = {
      httpOnly: this.httpOnly,
      path: this.cookiePath,
      secure: this.secure,
    };

    if (expire) {
      options.expires = new Date(Date.parse('01 Jan 2010'));
    } else if (this.maxAge !== undefined) {
      // insane; Express wants this in milliseconds
      options.maxAge = this.maxAge * 1000;
    }

    if (this.sameSite !== undefined) {
      options.sameSite = this.sameSite;
    }

    res.cookie(this.cookieName, value, options);
  }

  interceptWriteHeaders(res: Response, callback: () => void): void {
    // eslint-disable-next-line @typescript-eslint/unbound-method
    const realWriteHead = res.writeHead;

    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    res.writeHead = ((
      statusCode: number,
      reasonOrHeaders?: string | OutgoingHttpHeaders,
      headers?: OutgoingHttpHeaders | OutgoingHttpHeader[],
    ): Response => {
      // set our encrypted cookie, if necessary
      callback();

      // ensure arguments.length is right
      const args: [
        number,
        (string | OutgoingHttpHeaders | OutgoingHttpHeader[] | undefined)?,
        (OutgoingHttpHeaders | OutgoingHttpHeader[] | undefined)?,
      ] = [statusCode];
      if (reasonOrHeaders !== undefined) {
        args.push(reasonOrHeaders);
        if (headers !== undefined) {
          args.push(headers);
        }
      }

      // TODO: remove this any cast in the future -- for now,
      // typescript can't quite handle the insanity of Node's
      // writeHead's signature
      return realWriteHead.apply(res, args as any);
    }) as any;
  }

  handle = (req: Request, res: Response, next: NextFunction): void => {
    if (req.cookies === undefined) {
      throw new Error('seshcookie requires the cookie-parser middleware be installed before it.');
    }
    if (req.session !== undefined) {
      throw new Error('WARNING: session not empty; check your middleware stack.');
    }

    let hadCookie = false;
    let originalSerializedSession: undefined | string;

    if (req.cookies && req.cookies[this.cookieName]) {
      hadCookie = true;
      const cookie = req.cookies[this.cookieName] as string;

      try {
        const plaintext = decrypt(cookie, this.key);
        originalSerializedSession = plaintext;
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        req.session = JSON.parse(plaintext) as Express.SessionData;
      } catch (error) {
        // console.log(`cookie decryption failed: ${error}`);
      }
    }

    if (req.session === undefined) {
      req.session = {};
    }

    this.interceptWriteHeaders(res, () => {
      if (Object.keys(req.session).length === 0) {
        if (hadCookie) {
          // session has been emptied out; need to delete cookie.
          this.setCookie(res, '', true);
        }

        return;
      }

      const contents = JSON.stringify(req.session);
      if (contents === originalSerializedSession) {
        // session hasn't changed; don't re-set the cookie
        return;
      }

      const ciphertext = encrypt(Buffer.from(contents), this.key);
      this.setCookie(res, ciphertext);
    });

    next();
    // tslint:disable-next-line
  };
}

export function seshcookie(options: Options): RequestHandler {
  const seshCookie = new SeshCookie(options);
  return seshCookie.handle;
}

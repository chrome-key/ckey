//  Instead of re-writing all of the webauthn types, handle byte arrays manually
export function webauthnStringify(o) {
  return JSON.stringify(o, (k, v) => {
    if (v) {
      if (v.constructor.name === 'ArrayBuffer') {
        v = new Uint8Array(v);
      }
      if (v.constructor.name === 'Uint8Array') {
        return {
          data: Buffer.from(v).toString('base64'),
          kr_ser_ty: 'Uint8Array',
        };
      }
    }
    return v;
  });
}

export function webauthnParse(j) {
  return JSON.parse(j, (k, v) => {
    if (v && v.kr_ser_ty === 'Uint8Array') {
      return Uint8Array.from(Buffer.from(v.data, 'base64'));
    }
    if (v && v.kr_ser_ty === 'ArrayBuffer') {
      return Buffer.from(v.data, 'base64').buffer;
    }
    return v;
  });
}

export function concatenate(...arrays: Uint8Array[]) {
  const totalLength = arrays.map(({ length }) => length).reduce((v1, v2) => v1 + v2, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

export function counterToBytes(c: number): Uint8Array {
  const bytes = new Uint8Array(4);
  // Sadly, JS TypedArrays are whatever-endian the platform is,
  // so Uint32Array is not at all useful here (or anywhere?),
  // and we must manually pack the counter (big endian as per spec).
  bytes[0] = 0xFF & c >>> 24;
  bytes[1] = 0xFF & c >>> 16;
  bytes[2] = 0xFF & c >>> 8;
  bytes[3] = 0xFF & c;
  return bytes;
}

/*export function pemToArrayBuffer(pem) {
  var b64Lines = removeLines(pem);
  var b64Prefix = b64Lines.replace('-----BEGIN PRIVATE KEY-----', '');
  var b64Final = b64Prefix.replace('-----END PRIVATE KEY-----', '');

  return base64ToArrayBuffer(b64Final);
}

function removeLines(str) {
  return str.replace("\n", "");
}*/

// Copyright 2014 Google Inc. All rights reserved
//
// Use of this source code is governed by a BSD-style
// license that can be found at
// https://developers.google.com/open-source/licenses/bsd
/**
 * Gets the scheme + origin from a web url.
 * @param {string} url Input url
 * @return {?string} Scheme and origin part if url parses
 */
export function getOriginFromUrl(url: string): string | null {
  const re = new RegExp('^(https?://)[^/]+/?');
  const originarray = re.exec(url);
  if (originarray == null) { return null; }
  let origin = originarray[0];
  while (origin.charAt(origin.length - 1) === '/') {
    origin = origin.substring(0, origin.length - 1);
  }
  return origin;
}

export function getDomainFromOrigin(origin: string): string {
  return origin.replace(new RegExp('^https?://'), '')
    .replace(new RegExp(':[0-9]+$'), '');
}

export function byteArrayToBase64(arr: Uint8Array, urlEncoded: boolean = false): string {
  const result = btoa(String.fromCharCode(...arr));
  if (urlEncoded) {
    return result.replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
  }
  return result;
}

export function base64ToByteArray(str: string, urlEncoded: boolean = false): Uint8Array {
  let rawInput = str;
  if (urlEncoded) {
    rawInput = padString(rawInput)
      .replace(/\-/g, '+')
      .replace(/_/g, '/');
  }
  return Uint8Array.from(atob(rawInput), (c) => c.charCodeAt(0));
}

export function padString(input: string): string {
  let result = input;
  while (result.length % 4) {
    result += '=';
  }
  return result;
}

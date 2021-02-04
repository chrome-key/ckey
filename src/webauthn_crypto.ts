import * as asn1 from 'asn1.js';
import {BN} from 'bn.js';
import {base64ToByteArray} from "./utils";
import {ES256, ES256_COSE, SHA256_COSE} from "./constants";

export interface ICOSECompatibleKey {
    algorithm: number;
    privateKey?: CryptoKey;
    publicKey?: CryptoKey;
    toCOSE(key: CryptoKey): Promise<Map<number, any>>;
    sign(data: Uint8Array): Promise<Uint8Array>
}

export class ECDSA implements ICOSECompatibleKey {
    public algorithm: number
    public privateKey?: CryptoKey
    public publicKey?: CryptoKey

    public static async fromKey(key: CryptoKey): Promise<ECDSA> {
        if (key.type === 'public') {
            return new ECDSA(ES256_COSE, null, key);
        } else {
            return new ECDSA(ES256_COSE, key);
        }
    }

    public static async createECDSAKeyPair(): Promise<ECDSA> {
        const keyPair = await window.crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: ES256 },
            true,
            ['sign'],
        );
        return new ECDSA(ES256_COSE, keyPair.privateKey, keyPair.publicKey);
    }

    constructor(
        algorithm: number,
        privateKey: CryptoKey,
        publicKey?: CryptoKey,
    ) {
        this.algorithm = algorithm;
        this.privateKey = privateKey;
        if (publicKey) {
            this.publicKey = publicKey;
        }
    }

    public async toCOSE(key: CryptoKey): Promise<Map<number, any>> {
        // In JWK the X and Y portions are Base64URL encoded (https://tools.ietf.org/html/rfc7517#section-3),
        // which is just the right type for COSE encoding (https://tools.ietf.org/html/rfc8152#section-7),
        // we just need to convert it to a byte array.
        const exportedKey = await window.crypto.subtle.exportKey('jwk', key);
        const attData = new Map();
        attData.set(1, 2); // EC2 key type
        attData.set(3, this.algorithm);
        attData.set(-1, SHA256_COSE);
        attData.set(-2, base64ToByteArray(exportedKey.x, true));
        attData.set(-3, base64ToByteArray(exportedKey.y, true));
        return attData;
    }

    public async sign(data: Uint8Array): Promise<Uint8Array> {
        if (!this.privateKey) {
            throw new Error('no private key available for signing');
        }
        const rawSign = await window.crypto.subtle.sign( // Creates digest Hash before signing
         { name: 'ECDSA', hash: 'SHA-256' },
            this.privateKey,
            data,
        );

        const rawSignBuf = new Buffer(rawSign);

        // Credit to: https://stackoverflow.com/a/39651457/5333936
        const ecdsaDerSig = asn1.define('ECPrivateKey', function() {
            return this.seq().obj(
                this.key('r').int(),
                this.key('s').int(),
            );
        });
        const r = new BN(rawSignBuf.slice(0, 32).toString('hex'), 16, 'be');
        const s = new BN(rawSignBuf.slice(32).toString('hex'), 16, 'be');
        return new Uint8Array(ecdsaDerSig.encode({r, s}, 'der'));
    }
}

export async function importFromJWK(jwk, usages): Promise<CryptoKey> {
    return window.crypto.subtle.importKey(
        'jwk',
        jwk,
        {
            name: 'ECDSA',
            namedCurve: ES256,
        },
        true,
        usages,
    );
}
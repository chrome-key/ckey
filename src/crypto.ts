import * as CBOR from 'cbor';
import { getLogger } from './logging';
import { base64ToByteArray, byteArrayToBase64 } from './utils';
import * as asn1 from 'asn1.js';
import { BN } from 'bn.js';

const log = getLogger('crypto');

// Generated with pseudo random values via
// https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
const CKEY_ID = new Uint8Array([
    194547236, 76082241, 3628762690, 4137210381,
    1214244733, 1205845608, 840015201, 3897052717,
    4072880437, 4027233456, 675224361, 2305433287,
    74291263, 3461796691, 701523034, 3178201666,
    3992003567, 1410532, 4234129691, 1438515639,
]);

// Copied from krypton
function counterToBytes(c: number): Uint8Array {
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

const coseEllipticCurveNames: { [s: number]: string } = {
    1: 'SHA-256',
};

const ellipticNamedCurvesToCOSE: { [s: string]: number } = {
    'P-256': -7,
};

interface ICOSECompatibleKey {
    algorithm: number;
    privateKey: CryptoKey;
    publicKey?: CryptoKey;
    generateClientData(challenge: ArrayBuffer, extraOptions: any): Promise<string>;
    generateAuthenticatorData(rpID: string, counter: number, credentialID: Uint8Array): Promise<Uint8Array>;
    sign(data: Uint8Array): Promise<ArrayBuffer>;
}

class ECDSA implements ICOSECompatibleKey {

    public static async fromKey(key: CryptoKey): Promise<ECDSA> {
        return new ECDSA(ellipticNamedCurvesToCOSE[(key.algorithm as EcKeyAlgorithm).namedCurve], key);
    }

    public static async fromCOSEAlgorithm(algorithm: number): Promise<ECDSA> {
        // Creating the key
        let namedCurve: string;
        for (const k in ellipticNamedCurvesToCOSE) {
            if (ellipticNamedCurvesToCOSE[k] === algorithm) {
                namedCurve = k;
                break;
            }
        }
        if (!namedCurve) {
            throw new Error(`could not find a named curve for algorithm ${algorithm}`);
        }
        const keyPair = await window.crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve },
            true,
            ['sign'],
        );
        return new ECDSA(algorithm, keyPair.privateKey, keyPair.publicKey);
    }

    /**
     * This maps a COSE algorithm ID https://www.iana.org/assignments/cose/cose.xhtml#algorithms
     * to its respective COSE curve ID // Based on https://tools.ietf.org/html/rfc8152#section-13.1.
     */
    private static ellipticCurveKeys: { [s: number]: number } = {
        [-7]: 1,
        [-35]: 2,
        [-36]: 3,
    };

    constructor(
        public algorithm: number,
        public privateKey: CryptoKey,
        public publicKey?: CryptoKey,
    ) {
        if (!(algorithm in ECDSA.ellipticCurveKeys)) {
            throw new Error(`unknown ECDSA algorithm ${algorithm}`);
        }
    }

    public async generateClientData(challenge: ArrayBuffer, extraOptions: any): Promise<string> {
        return JSON.stringify({
            challenge: byteArrayToBase64(Buffer.from(challenge), true),
            hashAlgorithm: coseEllipticCurveNames[ECDSA.ellipticCurveKeys[this.algorithm]],
            ...extraOptions,
        });
    }

    public async generateAuthenticatorData(rpID: string, counter: number, credentialID: Uint8Array): Promise<Uint8Array> {
        const rpIdDigest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpID));
        const rpIdHash = new Uint8Array(rpIdDigest);

        // CKEY_ID is a HAD-specific ID
        let aaguid: Uint8Array;
        let credIdLen: Uint8Array;
        let encodedKey: Uint8Array;

        let authenticatorDataLength = rpIdHash.length + 1 + 4;
        if (this.publicKey) {
            aaguid = CKEY_ID.slice(0, 16);
            // 16-bit unsigned big-endian integer.
            credIdLen = new Uint8Array(2);
            credIdLen[0] = (credentialID.length >> 8) & 0xff;
            credIdLen[1] = credentialID.length & 0xff;
            const coseKey = await this.toCOSE(this.publicKey);
            encodedKey = new Uint8Array(CBOR.encode(coseKey));
            authenticatorDataLength += aaguid.length
                + credIdLen.byteLength
                + credentialID.length
                + encodedKey.byteLength;
        }

        const authenticatorData = new Uint8Array(authenticatorDataLength);
        let offset = 0;

        // 32 bytes for the RP ID hash
        authenticatorData.set(rpIdHash, 0);
        offset += rpIdHash.length;

        // 1 byte for flags
        // user-presence flag goes on the right-most bit
        authenticatorData[rpIdHash.length] = 1;
        if (this.publicKey) {
            // attestation flag goes on the 7th bit (from the right)
            authenticatorData[rpIdHash.length] |= (1 << 6);
        }
        offset++;

        // 4 bytes for the counter. big-endian uint32
        // https://www.w3.org/TR/webauthn/#signature-counter
        authenticatorData.set(counterToBytes(counter), offset);
        offset += counterToBytes(counter).length;

        if (!this.publicKey) {
            return authenticatorData;
        }

        // 16 bytes for the Authenticator Attestation GUID
        authenticatorData.set(aaguid, offset);
        offset += aaguid.length;

        // 2 bytes for the credential ID length. 16-bit unsigned big-endian integer.
        authenticatorData.set(credIdLen, offset);
        offset += credIdLen.byteLength;

        // Variable length credential ID
        authenticatorData.set(credentialID, offset);
        offset += credentialID.length;

        // Variable length public key
        authenticatorData.set(encodedKey, offset);

        return authenticatorData;
    }

    public async sign(data: Uint8Array): Promise<ArrayBuffer> {
        if (!this.privateKey) {
            throw new Error('no private key available for signing');
        }
        const rawSign = await window.crypto.subtle.sign(
            this.getKeyParams(),
            this.privateKey,
            data,
        );

        const rawSignBuf = new Buffer(rawSign);

        // Credit to: https://stackoverflow.com/a/39651457/5333936
        const EcdsaDerSig = asn1.define('ECPrivateKey', function() {
            return this.seq().obj(
                this.key('r').int(),
                this.key('s').int()
            );
        });
        const r = new BN(rawSignBuf.slice(0, 32).toString('hex'), 16, 'be');
        const s = new BN(rawSignBuf.slice(32).toString('hex'), 16, 'be');
        return EcdsaDerSig.encode({r, s}, 'der');
    }

    private getKeyParams(): EcdsaParams {
        return { name: 'ECDSA', hash: coseEllipticCurveNames[ECDSA.ellipticCurveKeys[this.algorithm]] };
    }

    private async toCOSE(key: CryptoKey): Promise<Map<number, any>> {
        // In JWK the X and Y portions are Base64URL encoded (https://tools.ietf.org/html/rfc7517#section-3),
        // which is just the right type for COSE encoding (https://tools.ietf.org/html/rfc8152#section-7),
        // we just need to convert it to a byte array.
        const exportedKey = await window.crypto.subtle.exportKey('jwk', key);
        const attData = new Map();
        attData.set(1, 2); // EC2 key type
        attData.set(3, this.algorithm);
        attData.set(-1, ECDSA.ellipticCurveKeys[this.algorithm]);
        attData.set(-2, base64ToByteArray(exportedKey.x, true));
        attData.set(-3, base64ToByteArray(exportedKey.y, true));
        return attData;
    }
}

// ECDSA w/ SHA-256
const defaultPKParams = { alg: -7, type: 'public-key' };
const coseAlgorithmToKeyName = {
    [-7]: 'ECDSA',
};

export const getCompatibleKey = (pkParams: PublicKeyCredentialParameters[]): Promise<ICOSECompatibleKey> => {
    for (const params of (pkParams || [defaultPKParams])) {
        const algorithmName = coseAlgorithmToKeyName[params.alg];
        if (!algorithmName) {
            continue;
        }
        switch (algorithmName) {
            case 'ECDSA':
                return ECDSA.fromCOSEAlgorithm(params.alg);
            default:
                throw new Error(`unsupported key algorithm ${algorithmName}`);
        }
    }
    throw new Error(`unable to get key`);
};

export const getCompatibleKeyFromCryptoKey = (key: CryptoKey): Promise<ICOSECompatibleKey> => {
    switch (key.algorithm.name) {
        case 'ECDSA':
            return ECDSA.fromKey(key);
        default:
            throw new Error(`unsupported key algorithm ${key.algorithm.name}`);
    }
};

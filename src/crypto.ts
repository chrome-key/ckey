import * as CBOR from 'cbor';
import { getLogger } from './logging';
import { base64ToByteArray, byteArrayToBase64 } from './utils';

const log = getLogger('crypto');

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

export interface ICOSECompatibleKey {
    algorithm: number;
    privateKey?: CryptoKey;
    publicKey?: CryptoKey;
    generateClientData(challenge: ArrayBuffer, extraOptions: any): Promise<string>;
    generateAuthenticatorData(rpID: string, counter: number, credentialId: Uint8Array, extensionOutput: Uint8Array): Promise<Uint8Array>;
    sign(clientData: Uint8Array): Promise<ArrayBuffer>;
    toCOSE(key: CryptoKey): Promise<Map<number, any>>;
}

class ECDSA implements ICOSECompatibleKey {

    public static async fromKey(key: CryptoKey): Promise<ECDSA> {
        if (key.type === "public") {
            return new ECDSA(ellipticNamedCurvesToCOSE[(key.algorithm as EcKeyAlgorithm).namedCurve], null, key);
        } else {
            return new ECDSA(ellipticNamedCurvesToCOSE[(key.algorithm as EcKeyAlgorithm).namedCurve], key);
        }
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

    public async generateAuthenticatorData(rpID: string, counter: number, credentialId: Uint8Array, extensionOutput: Uint8Array = null): Promise<Uint8Array> {
        const rpIdDigest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpID));
        const rpIdHash = new Uint8Array(rpIdDigest);

        // CKEY_ID is a HAD-specific ID
        let aaguid: Uint8Array;
        let credIdLen: Uint8Array;
        let encodedKey: Uint8Array;

        let authenticatorDataLength = rpIdHash.length + 1 + 4;
        if (this.publicKey) {
            aaguid = credentialId.slice(0, 16);
            // 16-bit unsigned big-endian integer.
            credIdLen = new Uint8Array(2);
            credIdLen[0] = (credentialId.length >> 8) & 0xff;
            credIdLen[1] = credentialId.length & 0xff;
            const coseKey = await this.toCOSE(this.publicKey);
            encodedKey = new Uint8Array(CBOR.encode(coseKey));
            authenticatorDataLength += aaguid.length
                + credIdLen.length
                + credentialId.length
                + encodedKey.length;
        }

        if (extensionOutput != null) {
            authenticatorDataLength += extensionOutput.byteLength;
        }

        const authenticatorData = new Uint8Array(authenticatorDataLength);
        let offset = 0;

        // 32 bytes for the RP ID hash
        authenticatorData.set(rpIdHash, 0);
        offset += rpIdHash.length;

        // 1 byte for flags
        authenticatorData[rpIdHash.length] = 1; // User presence (Bit 0)
        if (this.publicKey) {
            // attestation flag goes on the 7th bit (from the right)
            authenticatorData[rpIdHash.length] |= (1 << 6); // Attestation present (Bit 6)
        }
        if (extensionOutput != null) {
            authenticatorData[rpIdHash.length] |= (1 << 7); // Extension present (Bit 7)
        }
        offset++;

        // 4 bytes for the counter. big-endian uint32
        // https://www.w3.org/TR/webauthn/#signature-counter
        authenticatorData.set(counterToBytes(counter), offset);
        offset += counterToBytes(counter).length;

        if (!this.publicKey) {
            if (extensionOutput != null) { // Extension for assertion
                authenticatorData.set(extensionOutput, offset);
            }
            return authenticatorData;
        }

        // attestedCredentialData

        // 16 bytes for the Authenticator Attestation GUID
        authenticatorData.set(aaguid, offset);
        offset += aaguid.length;

        // 2 bytes for the authenticator key ID length. 16-bit unsigned big-endian integer.
        authenticatorData.set(credIdLen, offset);
        offset += credIdLen.length;

        // Variable length authenticator key ID
        authenticatorData.set(credentialId, offset);
        offset += credentialId.length;

        // Variable length public key
        authenticatorData.set(encodedKey, offset);
        offset += encodedKey.length;

        // Variable length for extension
        if (extensionOutput != null) {
            authenticatorData.set(extensionOutput, offset);
        }

        return authenticatorData;
    }

    public async sign(data: Uint8Array): Promise<ArrayBuffer> {
        if (!this.privateKey) {
            throw new Error('no private key available for signing');
        }
        const tmpSign = await window.crypto.subtle.sign(
            this.getKeyParams(),
            this.privateKey,
            data,
        )

        const rawSig = new Buffer(tmpSign)

        // Credit to: https://stackoverflow.com/a/39651457/5333936
        const asn1 = require('asn1.js');
        const BN = require('bn.js');

        const EcdsaDerSig = asn1.define('ECPrivateKey', function() {
            return this.seq().obj(
                this.key('r').int(),
                this.key('s').int()
            );
        });

        const r = new BN(rawSig.slice(0, 32).toString('hex'), 16, 'be');
        const s = new BN(rawSig.slice(32).toString('hex'), 16, 'be');
        return EcdsaDerSig.encode({r, s}, 'der');
    }

    private getKeyParams(): EcdsaParams {
        return { name: 'ECDSA', hash: coseEllipticCurveNames[ECDSA.ellipticCurveKeys[this.algorithm]] };
    }

    public async toCOSE(key: CryptoKey): Promise<Map<number, any>> {
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

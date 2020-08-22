import {base64ToByteArray} from "../../utils";

export const ES256_COSE = -7
export const ES256 = "P-256"
export const SHA256_COSE = 1

export interface ICOSECompatibleKey {
    algorithm: number;
    privateKey?: CryptoKey;
    publicKey?: CryptoKey;
    toCOSE(key: CryptoKey): Promise<Map<number, any>>;
}

export class ECDSA implements ICOSECompatibleKey {
    public algorithm: number
    public privateKey: CryptoKey
    public publicKey?: CryptoKey

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
}
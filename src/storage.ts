import { ivLength, keyExportFormat, saltLength } from './constants';
import { base64ToByteArray, byteArrayToBase64, concatenate } from './utils';
import {getLogger} from "./logging";

export const keyExists = (key: string): Promise<boolean> => {
    return new Promise<boolean>(async (res, rej) => {
        chrome.storage.sync.get(key, (resp) => {
            if (!!chrome.runtime.lastError) {
                rej(chrome.runtime.lastError);
            } else {
                res(!!resp[key]);
            }
        });
    });
};
// function hack() {
//     const keyID = 'V2E2TGQ1RnFqdEJNUVFncG0rUFBxS0UvVTBzcklnTTRVeHhOQWVZU0ZaZz1Ad2ViYXV0aG4ubWU=';
//     chrome.storage.sync.get(keyID, async (resp) => {
//         const raw = resp[keyID];
//         console.log('breaking', raw);
//         console.time();
//         const enc = new TextEncoder();
//         const payload = Uint8Array.from(atob(raw), (c) => c.charCodeAt(0));
//         const saltByteLength = payload[0];
//         const ivByteLength = payload[1];
//         const keyAlgorithmByteLength = payload[2];
//         let offset = 3;
//         const salt = payload.subarray(offset, offset + saltByteLength);
//         offset += saltByteLength;
//         const iv = payload.subarray(offset, offset + ivByteLength);
//         offset += ivByteLength;
//         const keyAlgorithmBytes = payload.subarray(offset, offset + keyAlgorithmByteLength);
//         offset += keyAlgorithmByteLength;
//         const keyBytes = payload.subarray(offset);
//         for (let i = 0; i < 10000; i++) {
//             const pbkdf2Params = {
//                 hash: 'SHA-256',
//                 iterations: 100000,
//                 name: 'PBKDF2',
//                 salt,
//             };
//             const derivationKey = await window.crypto.subtle.importKey(
//                 'raw',
//                 enc.encode('' + i),
//                 { name: 'PBKDF2', length: 256 },
//                 false,
//                 ['deriveBits', 'deriveKey'],
//             );
//             const wrappingKey = await window.crypto.subtle.deriveKey(
//                 pbkdf2Params,
//                 derivationKey,
//                 { name: 'AES-GCM', length: 256 },
//                 true,
//                 ['wrapKey', 'unwrapKey'],
//             );
//             const wrapAlgorithm = {
//                 iv,
//                 name: 'AES-GCM',
//             };
//             const unwrappingKeyAlgorithm = JSON.parse(new TextDecoder().decode(keyAlgorithmBytes));
//             try {
//                 const realPrivateKey = await window.crypto.subtle.unwrapKey(
//                     'pkcs8',
//                     keyBytes,
//                     wrappingKey,
//                     wrapAlgorithm,
//                     unwrappingKeyAlgorithm,
//                     true,
//                     ['sign'],
//                 );
//                 console.log('Success', realPrivateKey, 'in');
//                 console.timeEnd();
//                 return;
//             } catch (e) {
//                 if (i % 100 === 0) {
//                     console.log('Testing', i, 'Running for');
//                     console.timeLog();
//                 }
//             }
//         }
//     });
// }
export const deleteKey = (key: string) => {
    return new Promise(async (res, _) => {
        chrome.storage.sync.remove(key);
        res();
    });
};

const getWrappingKey = async (pin: string, salt: Uint8Array): Promise<CryptoKey> => {
    const enc = new TextEncoder();
    const derivationKey = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(pin),
        { name: 'PBKDF2', length: 256 },
        false,
        ['deriveBits', 'deriveKey'],
    );
    const pbkdf2Params: Pbkdf2Params = {
        hash: 'SHA-256',
        iterations: 100000,
        name: 'PBKDF2',
        salt,
    };
    return window.crypto.subtle.deriveKey(
        pbkdf2Params,
        derivationKey,
        { name: 'AES-GCM', length: 256 },
        true,
        ['wrapKey', 'unwrapKey'],
    );
};

const log = getLogger('webauthn');

export const fetchKey = async (key: string, pin: string): Promise<CryptoKey> => {
    log.info("A")
    return new Promise<CryptoKey>(async (res, rej) => {
        chrome.storage.sync.get(key, async (resp) => {
            log.info(key)
            if (!!chrome.runtime.lastError) {
                rej(chrome.runtime.lastError);
                return;
            }
            log.info(resp.key)
            const payload = base64ToByteArray(resp[key]);
            const saltByteLength = payload[0];
            const ivByteLength = payload[1];
            const keyAlgorithmByteLength = payload[2];
            let offset = 3;
            const salt = payload.subarray(offset, offset + saltByteLength);
            offset += saltByteLength;
            const iv = payload.subarray(offset, offset + ivByteLength);
            offset += ivByteLength;
            const keyAlgorithmBytes = payload.subarray(offset, offset + keyAlgorithmByteLength);
            offset += keyAlgorithmByteLength;
            const keyBytes = payload.subarray(offset);

            const wrappingKey = await getWrappingKey(pin, salt);
            const wrapAlgorithm: AesGcmParams = {
                iv,
                name: 'AES-GCM',
            };
            const unwrappingKeyAlgorithm = JSON.parse(new TextDecoder().decode(keyAlgorithmBytes));
            window.crypto.subtle.unwrapKey(
                keyExportFormat,
                keyBytes,
                wrappingKey,
                wrapAlgorithm,
                unwrappingKeyAlgorithm,
                true,
                ['sign'],
            ).then(res, rej);
        });
    });
};

export const saveKey = (key: string, privateKey: CryptoKey, pin: string): Promise<void> => {
    return new Promise<void>(async (res, rej) => {
        if (!pin) {
            rej('no pin provided');
            return;
        }
        const salt = window.crypto.getRandomValues(new Uint8Array(saltLength));
        const wrappingKey = await getWrappingKey(pin, salt);
        const iv = window.crypto.getRandomValues(new Uint8Array(ivLength));
        const wrapAlgorithm: AesGcmParams = {
            iv,
            name: 'AES-GCM',
        };

        const wrappedKeyBuffer = await window.crypto.subtle.wrapKey(
            keyExportFormat,
            privateKey,
            wrappingKey,
            wrapAlgorithm,
        );
        const wrappedKey = new Uint8Array(wrappedKeyBuffer);
        const keyAlgorithm = new TextEncoder().encode(JSON.stringify(privateKey.algorithm));
        const payload = concatenate(
            Uint8Array.of(saltLength, ivLength, keyAlgorithm.length),
            salt,
            iv,
            keyAlgorithm,
            wrappedKey);
        log.info(payload)
        log.info(key)
        chrome.storage.sync.set({ [key]: byteArrayToBase64(payload) }, () => {
            if (!!chrome.runtime.lastError) {
                log.info("Key not stored")
                rej(chrome.runtime.lastError);
            } else {
                log.info("Key stored")
                res();
            }
        });
    });
};

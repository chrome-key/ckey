import {ivLength, keyExportFormat, saltLength} from './constants';
import {base64ToByteArray, byteArrayToBase64, concatenate} from './utils';
import {getLogger} from "./logging";
import {ExportContainer, ExportContainerType} from "./recovery";

const log = getLogger('storage');

export const keyExists = (key: string): Promise<boolean> => {
    return new Promise<boolean>(async (res, rej) => {
        chrome.storage.sync.get({[key]: null}, (resp) => {
            if (!!chrome.runtime.lastError) {
                rej(chrome.runtime.lastError);
            } else {
                res(!(resp[key] == null));
            }
        });
    });
};

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
        {name: 'PBKDF2', length: 256},
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
        {name: 'AES-GCM', length: 256},
        true,
        ['wrapKey', 'unwrapKey'],
    );
};

export async function saveExportContainer(cType: ExportContainerType, container: Array<ExportContainer>): Promise<void> {
    let exportJSON = JSON.stringify(container);

    log.debug(`Storing ${cType} container`, exportJSON);

    return new Promise<void>(async (res, rej) => {
        chrome.storage.sync.set({[cType]: exportJSON}, () => {
            if (!!chrome.runtime.lastError) {
                rej(chrome.runtime.lastError);
            } else {
                res();
            }
        });
    });
}

export async function fetchExportContainer(cType: ExportContainerType): Promise<Array<ExportContainer>> {
    return new Promise<Array<ExportContainer>>(async (res, rej) => {
        chrome.storage.sync.get({[cType]: null}, async (resp) => {
            if (!!chrome.runtime.lastError) {
                log.warn(`Could not fetch ${cType} container`);
                rej(chrome.runtime.lastError);
                return;
            }

            if (resp[cType] == null) {
                return rej(`Container ${cType} not found`);
            }

            let exportJSON = await JSON.parse(resp[cType]);
            let exportContainer = new Array<ExportContainer>();
            let i;
            for (i = 0; i < exportJSON.length; ++i) {
                exportContainer.push(new ExportContainer(exportJSON[i].id, exportJSON[i].payload));
            }
            res(exportContainer);
        });
    });
}

export const fetchKey = async (key: string, pin: string): Promise<CryptoKey> => {
    log.debug('Fetching key for', key);
    return new Promise<CryptoKey>(async (res, rej) => {
        chrome.storage.sync.get({[key]: null}, async (resp) => {
            if (!!chrome.runtime.lastError) {
                rej(chrome.runtime.lastError);
                return;
            }
            if (resp[key] == null) {
                return rej("Key not found");
            }
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

        chrome.storage.sync.set({[key]: byteArrayToBase64(payload)}, () => {
            if (!!chrome.runtime.lastError) {
                rej(chrome.runtime.lastError);
            } else {
                res();
            }
        });
    });
};

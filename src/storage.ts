import {ivLength, keyExportFormat, saltLength} from './constants';

import {base64ToByteArray, byteArrayToBase64, concatenate} from './utils';

import {getLogger} from './logging';

import {ExportContainer, ExportContainerType} from './recovery';

const log = getLogger('storage');

// https://www.w3.org/TR/webauthn/#public-key-credential-source
export class PublicKeyCredentialSource {
    public static async exits (id: string): Promise<boolean> {
        return new Promise<boolean>(async (res, rej) => {
            chrome.storage.sync.get({[id]: null}, async (resp) => {
                if (!!chrome.runtime.lastError) {
                    rej(chrome.runtime.lastError);
                } else {
                    res(!(resp[id] == null));
                }
            });
        });
    };

    public static async load(id: string, pin: string): Promise<PublicKeyCredentialSource> {
        log.debug('Loading public key credential source for',id);
        return new Promise<PublicKeyCredentialSource>(async (res, rej) => {
            chrome.storage.sync.get({[id]: null}, async (resp) => {
                if (!!chrome.runtime.lastError) {
                    rej(chrome.runtime.lastError);
                    return;
                }
                if (resp[id] == null) {
                    return rej('Public key credential source not found');
                }

                const json = JSON.parse(resp[id]);

                const _id = json.id;
                const _rpId = json.rpId;
                const _userHandle = json.userHandle;

                const keyPayload = base64ToByteArray(json.privateKey);
                const saltByteLength = keyPayload[0];
                const ivByteLength = keyPayload[1];
                const keyAlgorithmByteLength = keyPayload[2];
                let offset = 3;
                const salt = keyPayload.subarray(offset, offset + saltByteLength);
                offset += saltByteLength;
                const iv = keyPayload.subarray(offset, offset + ivByteLength);
                offset += ivByteLength;
                const keyAlgorithmBytes = keyPayload.subarray(offset, offset + keyAlgorithmByteLength);
                offset += keyAlgorithmByteLength;
                const keyBytes = keyPayload.subarray(offset);

                const wrappingKey = await getWrappingKey(pin, salt);
                const wrapAlgorithm: AesGcmParams = {
                    iv,
                    name: 'AES-GCM',
                };
                const unwrappingKeyAlgorithm = JSON.parse(new TextDecoder().decode(keyAlgorithmBytes));
                const _privateKey = await window.crypto.subtle.unwrapKey(
                    keyExportFormat,
                    keyBytes,
                    wrappingKey,
                    wrapAlgorithm,
                    unwrappingKeyAlgorithm,
                    true,
                    ['sign'],
                );
                res(new PublicKeyCredentialSource(_id, _privateKey, _rpId, _userHandle));
            });
        });
    }

    public id: string
    public privateKey: CryptoKey
    public rpId: string
    public userHandle: string
    public type: string

    constructor(id: string, privateKey: CryptoKey, rpId: string, userHandle: string) {
        this.id = id;
        this.privateKey = privateKey;
        this.rpId = rpId;
        this.userHandle = userHandle;
        this.type = "public-key";
    }

    public async store(pin: string): Promise<void> {
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
                this.privateKey,
                wrappingKey,
                wrapAlgorithm,
            );
            const wrappedKey = new Uint8Array(wrappedKeyBuffer);
            const keyAlgorithm = new TextEncoder().encode(JSON.stringify(this.privateKey.algorithm));
            const payload = concatenate(
                Uint8Array.of(saltLength, ivLength, keyAlgorithm.length),
                salt,
                iv,
                keyAlgorithm,
                wrappedKey);

            const json = {
                id: this.id,
                privateKey: byteArrayToBase64(payload),
                rpId: this.rpId,
                userHandle: this.userHandle,
                type: this.type
            }

            chrome.storage.sync.set({[this.id]: JSON.stringify(json)}, () => {
                if (!!chrome.runtime.lastError) {
                    rej(chrome.runtime.lastError);
                } else {
                    res();
                }
            });
        });
    }
}

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

export async function saveExportContainer(cType: ExportContainerType, container: ExportContainer[]): Promise<void> {
    const exportJSON = JSON.stringify(container);

    log.debug(`Storing ${cType} container`, exportJSON);

    return new Promise<void>(async (res, rej) => {
        chrome.storage.local.set({[cType]: exportJSON}, () => {
            if (!!chrome.runtime.lastError) {
                log.error('Could not store container', chrome.runtime.lastError.message);
                rej(chrome.runtime.lastError);
            } else {
                res();
            }
        });
    });
}

export async function fetchExportContainer(cType: ExportContainerType): Promise<ExportContainer[]> {
    return new Promise<ExportContainer[]>(async (res, rej) => {
        chrome.storage.local.get({[cType]: null}, async (resp) => {
            if (!!chrome.runtime.lastError) {
                log.warn(`Could not fetch ${cType} container`);
                rej(chrome.runtime.lastError);
                return;
            }

            if (resp[cType] == null) {
                return rej(`Container ${cType} not found`);
            }

            const exportJSON = await JSON.parse(resp[cType]);
            const exportContainer = new Array<ExportContainer>();
            let i;
            for (i = 0; i < exportJSON.length; ++i) {
                exportContainer.push(new ExportContainer(exportJSON[i].id, exportJSON[i].payload));
            }
            res(exportContainer);
        });
    });
}

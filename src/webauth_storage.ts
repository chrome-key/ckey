import {base64ToByteArray, byteArrayToBase64, concatenate} from "./utils";
import {ivLength, keyExportFormat, PIN, saltLength} from "./constants";
import {getLogger} from "./logging";

const log = getLogger('auth_storage');


export class CredentialsMap {
    public static async put(rpId: string, credSrc: PublicKeyCredentialSource): Promise<void> {
        log.debug(`Storing credential map entry for ${rpId}`);
        const mapEntryExists = await this.exits(rpId);
        let credSrcs: PublicKeyCredentialSource[];
        if (mapEntryExists) {
            log.debug('Credential map entry does already exist. Update entry.');
            const entries = await this.load(rpId);
            entries.push(credSrc);
            credSrcs = entries;
        } else {
            log.debug('Credential map entry does not exist. Create new entry.');
            credSrcs = new Array(credSrc);
        }

        // Store PublicKeyCredentialSource as JSON
        let jsonArr = [];
        for (let i = 0; i < credSrcs.length; i++) {
            const json = await credSrcs[i].export();
            jsonArr.push(json);
        }
        let exportJSON = JSON.stringify(jsonArr);
        return new Promise<void>(async (res, rej) => {
            chrome.storage.local.set({[rpId]: exportJSON}, () => {
                if (!!chrome.runtime.lastError) {
                    log.error('Could not perform CredentialsMap.put', chrome.runtime.lastError.message);
                    rej(chrome.runtime.lastError);
                } else {
                    res();
                }
            });
        });
    }

    public static async load(rpId: string): Promise<PublicKeyCredentialSource[]> {
        log.debug(`Loading credential map entry for ${rpId}`);
        return new Promise<PublicKeyCredentialSource[]>(async (res, rej) => {
            chrome.storage.local.get({[rpId]: null}, async (resp) => {
                if (!!chrome.runtime.lastError) {
                    rej(chrome.runtime.lastError);
                    return;
                }

                if (resp[rpId] == null) {
                    log.warn(`CredentialsMap entry ${rpId} not found`);
                    res([]);
                }

                const exportJSON = await JSON.parse(resp[rpId]);
                const credSrcs = new Array<PublicKeyCredentialSource>();
                for (let i = 0; i < exportJSON.length; ++i) {
                    const credSrc =  await PublicKeyCredentialSource.import(exportJSON[i]);
                    credSrcs.push(credSrc);
                }
                log.debug('Loaded credential map entry successfully');
                res(credSrcs);
            });
        });
    }

    public static async lookup(rpId: string, credSrcId: string): Promise<PublicKeyCredentialSource | null> {
        const credSrcs = await this.load(rpId);
        const res = credSrcs.filter(x => x.id == credSrcId);
        if (res.length == 0) {
            return null;
        } else {
            return res[0];
        }
    }

    public static async exits(rpId: string): Promise<boolean> {
        return new Promise<boolean>(async (res, rej) => {
            chrome.storage.local.get({[rpId]: null}, async (resp) => {
                if (!!chrome.runtime.lastError) {
                    log.error('Could not perform CredentialsMap.exits', chrome.runtime.lastError.message);
                    rej(chrome.runtime.lastError);
                } else {
                    res(!(resp[rpId] == null));
                }
            });
        });
    };
}

export class PublicKeyCredentialSource {
    public static async import(json: any): Promise<PublicKeyCredentialSource> {
        log.debug('Import PublicKeyCredentialSource', json);
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

        const wrappingKey = await getWrappingKey(PIN, salt);
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
        log.debug('Imported PublicKeyCredentialSource with id', _id)
        return new PublicKeyCredentialSource(_id, _privateKey, _rpId, _userHandle);
    }

    public id: string
    public privateKey: CryptoKey
    public rpId: string
    public userHandle: Uint8Array
    public type: string

    constructor(id: string, privateKey: CryptoKey, rpId: string, userHandle?: Uint8Array) {
        this.id = id;
        this.privateKey = privateKey;
        this.rpId = rpId;
        if (userHandle) {
            this.userHandle = userHandle;
        } else {
            this.userHandle = null;
        }
        this.type = "public-key";
    }

    public async export(): Promise<any> {
        const salt = window.crypto.getRandomValues(new Uint8Array(saltLength));
        const wrappingKey = await getWrappingKey(PIN, salt);
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

        log.debug('Exported PublicKeyCredentialSource with id', this.id)
        return json;
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
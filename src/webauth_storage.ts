import {
    base64ToByteArray,
    byteArrayToBase64,
    concatenate,
} from "./utils";
import {
    BACKUP_KEY, BD,
    BD_ENDPOINT,
    DEFAULT_BD_ENDPOINT, ES256,
    ivLength,
    keyExportFormat,
    RECOVERY_KEY,
    saltLength,
    PIN
} from "./constants";
import {getLogger} from "./logging";
import {BackupKey, RecoveryKey} from "./webauthn_psk";

const log = getLogger('auth_storage');

export let SESSION_PIN = null

export class PinStorage {
    private static saltRounds = 10;
    public static setSessionPIN(pin: string) {
        SESSION_PIN = pin;
    }

    public static resetSessionPIN(): void {
        this.setSessionPIN(null);
    }

    public static getSessionPin(): string {
        if (SESSION_PIN == null) {
            throw new Error("No session PIN available");
        }
        return SESSION_PIN;
    }

    public static async getPinHash(): Promise<Uint8Array> {
        return new Promise<Uint8Array>(async (res, rej) => {
            chrome.storage.local.get({[PIN]: null}, async (resp) => {
                if (!!chrome.runtime.lastError) {
                    log.error('Could not perform PSKStorage.getPin', chrome.runtime.lastError.message);
                    rej(chrome.runtime.lastError);
                    return;
                }

                if (resp[PIN] == null) {
                    rej('No PIN available. Have you performed the setup for your authenticator?');
                }
                log.debug('Loaded PIN hash successfully');
                res(resp[PIN]);
            });
        });
    };

    public static async setPin(pin: string): Promise<void> {
        const bcrypt = require('bcryptjs');
        let hash = bcrypt.hashSync(pin, this.saltRounds);

        return new Promise<void>(async (res, rej) => {
            chrome.storage.local.set({[PIN]: hash}, () => {
                if (!!chrome.runtime.lastError) {
                    log.error('Could not perform PSKStorage.setPin', chrome.runtime.lastError.message);
                    rej(chrome.runtime.lastError);
                    return;
                } else {
                    log.debug('Set PIN successfully');
                    res();
                }
            });
        });
    }
}

export class PSKStorage {
        public static async getBDEndpoint(): Promise<string> {
        return new Promise<string>(async (res, rej) => {
            chrome.storage.local.get({[BD_ENDPOINT]: null}, async (resp) => {
                if (!!chrome.runtime.lastError) {
                    log.error('Could not perform PSKStorage.getBDEndpoint', chrome.runtime.lastError.message);
                    rej(chrome.runtime.lastError);
                    return;
                }

                if (resp[BD_ENDPOINT] == null) {
                    log.warn(`No endpoint found, use default endpoint`);
                    res(DEFAULT_BD_ENDPOINT);
                    return;
                }
                log.debug('Loaded BD endpoint successfully');
                res(resp[BD_ENDPOINT]);
            });
        });
    }

    public static async setBDEndpoint(endpoint: string): Promise<void> {
        log.debug('Set BD endpoint to', endpoint);
        return new Promise<void>(async (res, rej) => {
            chrome.storage.local.set({[BD_ENDPOINT]: endpoint}, () => {
                if (!!chrome.runtime.lastError) {
                    log.error('Could not perform PSKStorage.setBDEndpoint', chrome.runtime.lastError.message);
                    rej(chrome.runtime.lastError);
                    return;
                } else {
                    res();
                }
            });
        });
    }

    public static async storeBD(bdUUID: string): Promise<void> {
        log.debug('Store BD');
        let bds = await this.loadBDs();
        if (bds.includes(bdUUID)) {
            return;
        } else {
            bds = bds.concat(bdUUID);
            const exportJSON = JSON.stringify(bds);
            return new Promise<void>(async (res, rej) => {
                chrome.storage.local.set({[BD]: exportJSON}, () => {
                    if (!!chrome.runtime.lastError) {
                        log.error('Could not perform PSKStorage.storeBD', chrome.runtime.lastError.message);
                        rej(chrome.runtime.lastError);
                        return;
                    } else {
                        res();
                    }
                });
            });
        }

    }

    public static async loadBDs(): Promise<Array<string>> {
        log.debug(`Loading BDs`);
        return new Promise<Array<string>>(async (res, rej) => {
            chrome.storage.local.get({[BD]: null}, async (resp) => {
                if (!!chrome.runtime.lastError) {
                    log.error('Could not perform PSKStorage.loadBDs', chrome.runtime.lastError.message);
                    rej(chrome.runtime.lastError);
                    return;
                }

                if (resp[BD] == null) {
                    log.warn(`No BDs found`);
                    res([]);
                    return;
                }

                const bds = await JSON.parse(resp[BD]);
                log.debug('Loaded BDs successfully');
                res(bds);
            });
        });
    }

    public static async storeBackupKeys(backupKeys: BackupKey[], bdUUID: string, override: boolean = false): Promise<void> {
        log.debug(`Storing backup keys for`, bdUUID);
        const backupKeysExists = await this.existBackupKeys(bdUUID);
        if (backupKeysExists && !override) {
            log.debug('Backup keys already exist. Update entry.');
            const entries = await this.loadBackupKeys(bdUUID);
            backupKeys = entries.concat(backupKeys);
        }

        let exportJSON = JSON.stringify(backupKeys);
        return new Promise<void>(async (res, rej) => {
            chrome.storage.local.set({[BACKUP_KEY + '_' + bdUUID]: exportJSON}, () => {
                if (!!chrome.runtime.lastError) {
                    log.error('Could not perform PSKStorage.storeBackupKeys', chrome.runtime.lastError.message);
                    rej(chrome.runtime.lastError);
                    return;
                } else {
                    res();
                }
            });
        });
    };

    public static async loadBackupKeys(bdUUID: string): Promise<BackupKey[]> {
        log.debug(`Loading backup keys`);
        return new Promise<BackupKey[]>(async (res, rej) => {
            chrome.storage.local.get({[BACKUP_KEY + '_' + bdUUID]: null}, async (resp) => {
                if (!!chrome.runtime.lastError) {
                    log.error('Could not perform PSKStorage.loadBackupKeys', chrome.runtime.lastError.message);
                    rej(chrome.runtime.lastError);
                    return;
                }

                if (resp[BACKUP_KEY + '_' + bdUUID] == null) {
                    log.warn(`No backup keys found`);
                    res([]);
                    return;
                }

                const backupKeys = await JSON.parse(resp[BACKUP_KEY + '_' + bdUUID]);
                log.debug('Loaded backup keys successfully');
                res(backupKeys);
            });
        });
    }

    private static async existBackupKeys(bdUUID: string): Promise<boolean> {
        return new Promise<boolean>(async (res, rej) => {
            chrome.storage.local.get({[BACKUP_KEY + '_' + bdUUID]: null}, async (resp) => {
                if (!!chrome.runtime.lastError) {
                    log.error('Could not perform PSKStorage.existBackupKeys', chrome.runtime.lastError.message);
                    rej(chrome.runtime.lastError);
                    return;
                } else {
                    res(!(resp[BACKUP_KEY + '_' + bdUUID] == null));
                }
            });
        });
    };

    public static async storeRecoveryKeys(recoveryKeys: RecoveryKey[]): Promise<void> {
        log.debug('Storing recovery keys');

        recoveryKeys = recoveryKeys.concat(await this.loadRecoveryKeys());

        // Export recoveryKeys
        const exportKeys = []
        for (let i = 0; i < recoveryKeys.length; i++) {
            const recKey = recoveryKeys[i];
            const expPrvKey = await exportKey(recKey.privKey);
            const expPubKey = await window.crypto.subtle.exportKey('jwk', recKey.pubKey);

            const json = {
                backupKeyId: recKey.backupKeyId,
                pubKey: expPubKey,
                privKey: expPrvKey,
                delegationSignature: recKey.delegationSignature,
                bdData: recKey.bdData,
            }

            exportKeys.push(json)
        }

        let exportJSON = JSON.stringify(exportKeys);
        return new Promise<void>(async (res, rej) => {
            chrome.storage.local.set({[RECOVERY_KEY]: exportJSON}, () => {
                if (!!chrome.runtime.lastError) {
                    log.error('Could not perform PSKStorage.storeRecoveryKeys', chrome.runtime.lastError.message);
                    rej(chrome.runtime.lastError);
                    return;
                } else {
                    res();
                }
            });
        });
    }

    public static async recoveryKeyExists(backupKeyId: string): Promise<boolean> {
        log.debug('recoveryKeyExists: Requested backup key ID', backupKeyId);
        const recoveryKeys = await PSKStorage.loadRecoveryKeys();
        return recoveryKeys.filter(x => x.backupKeyId === backupKeyId).length > 0
    }

    public static async loadRecoveryKeys(privateKeyImport: boolean = true): Promise<RecoveryKey[]> {
        log.debug(`Loading recovery keys`);
        return new Promise<RecoveryKey[]>(async (res, rej) => {
            chrome.storage.local.get({[RECOVERY_KEY]: null}, async (resp) => {
                if (!!chrome.runtime.lastError) {
                    log.error('Could not perform PSKStorage.loadRecoveryKeys', chrome.runtime.lastError.message);
                    rej(chrome.runtime.lastError);
                    return;
                }

                if (resp[RECOVERY_KEY] == null) {
                    log.warn(`No recovery keys found`);
                    res([]);
                    return;
                }

                const exportJSON = await JSON.parse(resp[RECOVERY_KEY]);
                const recKeys = new Array<RecoveryKey>();
                for (let i = 0; i < exportJSON.length; ++i) {
                    const json = exportJSON[i];
                    const prvKey = privateKeyImport ? await importKey(json.privKey) : null;
                    const pubKey = await window.crypto.subtle.importKey(
                        'jwk',
                        json.pubKey,
                        {
                            name: 'ECDSA',
                            namedCurve: ES256,
                        },
                        true,
                        [],
                    );

                    const recKey =  new RecoveryKey(json.backupKeyId, pubKey, prvKey, json.delegationSignature, json.bdData);
                    recKeys.push(recKey);
                }
                log.debug('Loaded recovery keys successfully', recKeys);
                res(recKeys);
            });
        });
    }
}

export class CredentialsMap {
    public static async put(rpId: string, credSrc: PublicKeyCredentialSource): Promise<void> {
        log.debug(`Storing credential map entry for ${rpId}`);
        const mapEntryExists = await this.rpEntryExists(rpId);
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
                    return;
                } else {
                    res();
                }
            });
        });
    }



    public static async load(rpId: string, keyImport: boolean = true): Promise<PublicKeyCredentialSource[]> {
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
                    return;
                }

                const exportJSON = await JSON.parse(resp[rpId]);
                const credSrcs = new Array<PublicKeyCredentialSource>();
                for (let i = 0; i < exportJSON.length; ++i) {
                    const credSrc =  await PublicKeyCredentialSource.import(exportJSON[i], keyImport);
                    credSrcs.push(credSrc);
                }
                log.debug('Loaded credential map entry successfully');
                res(credSrcs);
            });
        });
    }

    public static async lookup(rpId: string, credSrcId: string, keyImport: boolean = true): Promise<PublicKeyCredentialSource | null> {
        const credSrcs = await this.load(rpId, keyImport);
        const res = credSrcs.filter(x => x.id == credSrcId);
        if (res.length == 0) {
            return null;
        } else {
            return res[0];
        }
    };

    public static async rpEntryExists(rpId: string): Promise<boolean> {
        return new Promise<boolean>(async (res, rej) => {
            chrome.storage.local.get({[rpId]: null}, async (resp) => {
                if (!!chrome.runtime.lastError) {
                    log.error('Could not perform CredentialsMap.exists', chrome.runtime.lastError.message);
                    rej(chrome.runtime.lastError);
                    return;
                } else {
                    res(!(resp[rpId] == null));
                }
            });
        });
    };
}

export class PublicKeyCredentialSource {
    public static async import(json: any, keyImport: boolean = true): Promise<PublicKeyCredentialSource> {
        const _id = json.id;
        const _rpId = json.rpId;
        const _userHandle = json.userHandle;
        const _privateKey = keyImport? await importKey(json.privateKey) : null;

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
        return {
            id: this.id,
            privateKey: await exportKey(this.privateKey),
            rpId: this.rpId,
            userHandle: this.userHandle,
            type: this.type
        };
    }
}

async function exportKey(key: CryptoKey): Promise<string> {
    const salt = window.crypto.getRandomValues(new Uint8Array(saltLength));
    const wrappingKey = await getWrappingKey(PinStorage.getSessionPin(), salt);
    const iv = window.crypto.getRandomValues(new Uint8Array(ivLength));
    const wrapAlgorithm: AesGcmParams = {
        iv,
        name: 'AES-GCM',
    };

    const wrappedKeyBuffer = await window.crypto.subtle.wrapKey(
        keyExportFormat,
        key,
        wrappingKey,
        wrapAlgorithm,
    );
    const wrappedKey = new Uint8Array(wrappedKeyBuffer);
    const keyAlgorithm = new TextEncoder().encode(JSON.stringify(key.algorithm));
    const payload = concatenate(
        Uint8Array.of(saltLength, ivLength, keyAlgorithm.length),
        salt,
        iv,
        keyAlgorithm,
        wrappedKey);

    return byteArrayToBase64(payload)
}

async function importKey(rawKey: string): Promise<CryptoKey> {
    const keyPayload = base64ToByteArray(rawKey);
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

    const wrappingKey = await getWrappingKey(PinStorage.getSessionPin(), salt);
    const wrapAlgorithm: AesGcmParams = {
        iv,
        name: 'AES-GCM',
    };
    const unwrappingKeyAlgorithm = JSON.parse(new TextDecoder().decode(keyAlgorithmBytes));
    return await window.crypto.subtle.unwrapKey(
        keyExportFormat,
        keyBytes,
        wrappingKey,
        wrapAlgorithm,
        unwrappingKeyAlgorithm,
        true,
        ['sign'],
    );
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
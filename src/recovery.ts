import * as CBOR from 'cbor';
import {getLogger} from "./logging";
import {getCompatibleKeyFromCryptoKey} from "./crypto";

const log = getLogger('recovery');

export const PSK: string = "psk"
const BACKUP: string = "backup"
const RECOVERY: string = "recovery"

export async function syncBackupKeys () {
    const bckpKeys = await loadBackupKeys();
    log.info("Loaded backup keys", bckpKeys);
    await storePSKKeys(BACKUP, bckpKeys)
}

class PSKKey {
    key: CryptoKey;
    id: string;
    constructor(key: CryptoKey, id: string) {
        this.key = key;
        this.id = id;
    }
}

class ExportKey {
    key: JsonWebKey;
    id: string;
    constructor(key: JsonWebKey, id: string) {
        this.key = key;
        this.id = id;
    }
}

export class BackupKey extends PSKKey {
}

export class RecoveryKey extends PSKKey {
}

export async function loadBackupKeys(): Promise<Array<BackupKey>> {
    log.info("Loading backup keys form JSON file")
    return new Promise<Array<BackupKey>>(function (resolve, reject) {
        let xhr = new XMLHttpRequest();
        xhr.open("GET", chrome.extension.getURL('/recovery/backup.json'), true);
        xhr.onload = async function () {
            let status = xhr.status;
            if (status == 200) {
                let jwk = JSON.parse(this.response);
                let i;
                let bckpKeys = new Array<BackupKey>()
                for (i = 0; i < jwk.length; ++i) {
                    let parsedKey = await parseJWK(jwk[i]);
                    bckpKeys.push(new BackupKey(parsedKey, jwk[i].kid));
                }
                await resolve(bckpKeys);
            } else {
                reject(status);
            }
        };
        xhr.send();
    });
}

async function parseJWK(jwk): Promise<CryptoKey> {
    return window.crypto.subtle.importKey(
        "jwk",
        jwk,
        {
            name: "ECDSA",
            namedCurve: "P-256"
        },
        true,
        []
    );
}



async function storePSKKeys(identifier: string, psk: Array<PSKKey>): Promise<void> {
    let exportKeys = new Array<ExportKey>();
    let i;
    for (i = 0; i < psk.length; ++i) {
        let parsedKey = await window.crypto.subtle.exportKey("jwk", psk[i].key);
        exportKeys.push(new ExportKey(parsedKey, psk[i].id));
    }
    let pskJSON = JSON.stringify(exportKeys);
    log.info("Storing psk keys", pskJSON);

    return new Promise<void>(async (res, rej) => {
        chrome.storage.sync.set({ [identifier]: pskJSON }, () => {
            if (!!chrome.runtime.lastError) {
                log.info("PSK keys not stored")
                rej(chrome.runtime.lastError);
            } else {
                log.info("PSK keys stored")
                res();
            }
        });
    });
}

async function fetchPSKKeys(identifier: string): Promise<Array<PSKKey>> {
        return new Promise<Array<PSKKey>>(async (res, rej) => {
            chrome.storage.sync.get(identifier, async (resp) => {
                if (!!chrome.runtime.lastError) {
                    log.info("Could not fetch PSK keys");
                    rej(chrome.runtime.lastError);
                    return;
                }

                let exportedKey = await JSON.parse(resp[identifier]);
                let pskKeys = new Array<PSKKey>();
                let i;
                for (i = 0; i < exportedKey.length; ++i) {
                    let parsedKey = await parseJWK(exportedKey[i].key);
                    pskKeys.push(new PSKKey(parsedKey, exportedKey[i].id));
                }
                log.info(pskKeys);
                res(pskKeys);
            });
        });
}

async function popPSKKey(identifier: string): Promise<PSKKey> {
    let pskKeys = await fetchPSKKeys(identifier);
    let key = pskKeys.pop();
    await storePSKKeys(identifier, pskKeys)
    return key;
}

export async function popBackupKey(): Promise<BackupKey> {
    return popPSKKey(BACKUP);
}

export async function pskSetupExtensionOutput(backupKey: BackupKey): Promise<Uint8Array> {
    let compatibleKey = await getCompatibleKeyFromCryptoKey(backupKey.key);
    let coseKey = await new Uint8Array(CBOR.encode(compatibleKey.toCOSE(backupKey.key)));

    let extOutput = new Map([[PSK, coseKey]]);
    return new Uint8Array(CBOR.encode(extOutput));
}
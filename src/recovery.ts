import * as CBOR from 'cbor';
import {getLogger} from "./logging";
import {getCompatibleKeyFromCryptoKey} from "./crypto";

const log = getLogger('recovery');

export const PSK: string = "psk"

export async function syncBackupKeys () {
    const bckpKeys = await loadBackupKeys();
    log.info("Loaded backup keys", bckpKeys);
    await storeBackupKeys("backup", bckpKeys)
}

export class BackupKey {
    key: CryptoKey;
    id: string;
    constructor(key: CryptoKey, id: string) {
        this.key = key;
        this.id = id;
    }
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
                    let parsedKey = await parseKey(jwk[i]);
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

async function parseKey(jwk): Promise<CryptoKey> {
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

class ExportKey {
    key: JsonWebKey;
    id: string;
    constructor(key: JsonWebKey, id: string) {
        this.key = key;
        this.id = id;
    }
}



async function storeBackupKeys(identifier: string, backupKeys: Array<BackupKey>): Promise<void> {
    let exportKeys = new Array<ExportKey>();
    let i;
    for (i = 0; i < backupKeys.length; ++i) {
        let parsedKey = await window.crypto.subtle.exportKey("jwk", backupKeys[i].key);
        exportKeys.push(new ExportKey(parsedKey, backupKeys[i].id));
    }
    let bckpJSON = JSON.stringify(exportKeys);
    log.info("Storing backup keys", bckpJSON);

    return new Promise<void>(async (res, rej) => {
        chrome.storage.sync.set({ [identifier]: bckpJSON }, () => {
            if (!!chrome.runtime.lastError) {
                log.info("Backup keys not stored")
                rej(chrome.runtime.lastError);
            } else {
                log.info("Backup keys stored")
                res();
            }
        });
    });
}

async function fetchBackupKeys(identifier: string): Promise<Array<BackupKey>> {
        return new Promise<Array<BackupKey>>(async (res, rej) => {
            chrome.storage.sync.get(identifier, async (resp) => {
                if (!!chrome.runtime.lastError) {
                    log.info("Could not fetch backup keys");
                    rej(chrome.runtime.lastError);
                    return;
                }

                let exportedKey = await JSON.parse(resp[identifier]);
                let bckpKeys = new Array<BackupKey>();
                let i;
                for (i = 0; i < exportedKey.length; ++i) {
                    let parsedKey = await parseKey(exportedKey[i].key);
                    bckpKeys.push(new BackupKey(parsedKey, exportedKey[i].id));
                }
                log.info(bckpKeys);
                res(bckpKeys);
            });
        });
}

export async function popBackupKey(identifier: string = "backup"): Promise<BackupKey> {
    let bckpKeys = await fetchBackupKeys(identifier);
    let key = bckpKeys.pop();
    await storeBackupKeys(identifier, bckpKeys)
    return key;
}

export async function pskOutput(backupKey: BackupKey): Promise<Uint8Array> {
    let compatibleKey = await getCompatibleKeyFromCryptoKey(backupKey.key);
    let coseKey = await new Uint8Array(CBOR.encode(compatibleKey.toCOSE(backupKey.key)));

    let extOutput = new Map([[PSK, coseKey]]);
    return new Uint8Array(CBOR.encode(extOutput));
}
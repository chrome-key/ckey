import * as CBOR from 'cbor';
import {getLogger} from "./logging";
import {getCompatibleKeyFromCryptoKey, ICOSECompatibleKey} from "./crypto";
import {base64ToByteArray, byteArrayToBase64, getDomainFromOrigin} from "./utils";
import {saveKey} from "./storage";

const log = getLogger('recovery');

export const PSK: string = "psk"
const BACKUP: string = "backup"
const RECOVERY: string = "recovery"
const DELEGATION: string = "delegation"

export async function syncBackupKeys (content) {
    let jwk = JSON.parse(content);
    let i;
    let bckpKeys = new Array<BackupKey>()
    for (i = 0; i < jwk.length; ++i) {
        let parsedKey = await parseJWK(jwk[i], []);
        let id = base64ToByteArray(jwk[i].kid, true);
        const encId = byteArrayToBase64(id, true);
        bckpKeys.push(new BackupKey(parsedKey, encId));
    }
    log.info("Loaded backup keys", bckpKeys);
    await storePSKKeys(BACKUP, bckpKeys);
}

export async function syncDelegation (content) {
    let rawDelegations = JSON.parse(content);
    let i;
    let del = new Array<Delegation>()
    for (i = 0; i < rawDelegations.length; ++i) {
        let sign = rawDelegations[i].signature;
        let bId = base64ToByteArray(rawDelegations[i].cred_id, true);
        const encBId = byteArrayToBase64(bId, true);
        del.push(new Delegation(sign, encBId, rawDelegations[i].public_key));
    }
    log.info("Loaded delegation", del);
    await storeDelegations(del);
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
    constructor(key: CryptoKey) {
        super(key, createId());
    }
}

class RecoveryMessage {
    backupCredId: string;
    delegationSignature: Uint8Array;
    pubKey: Uint8Array;
    attestationObject: Uint8Array;
    clientDataJSON: Uint8Array;

    constructor() {
        // Dummy
    }

    async init(delegation: Delegation, rkPub: ICOSECompatibleKey, origin: string, challenge: ArrayBuffer) {
        this.backupCredId = delegation.backupId;
        this.delegationSignature = base64ToByteArray(delegation.signature, true);

        // Create attestation object for new key
        const recoveryCredId = base64ToByteArray(delegation.replacementId);

        // ToDo New Credential should also contain recovery key
        // ToDo Use valid attestation response
        const authData = await rkPub.generateAuthenticatorData(origin, 0, recoveryCredId, null);
        log.debug('AuthData of recovery message', authData);

        const coseKey = await rkPub.toCOSE(rkPub.publicKey);
        this.pubKey = new Uint8Array(CBOR.encode(coseKey));

        this.attestationObject = CBOR.encodeCanonical({
            attStmt: new Map(),
            authData: authData,
            fmt: 'none',
        });


        const clientData = await rkPub.generateClientData(
         challenge,
            { origin, type: 'webauthn.create' },
        );
        this.clientDataJSON = base64ToByteArray(window.btoa(clientData), true);

    }

    encode(): ArrayBuffer {
        return CBOR.encodeCanonical({
            publicKey: this.pubKey,
            delegationSignature: byteArrayToBase64(this.delegationSignature),
            backupCredentialId: this.backupCredId,
            authAttData: {
                clientDataJSON: this.clientDataJSON,
                attestationObject: this.attestationObject
            },
        }).buffer;
    }
}

class Delegation {
    signature: string;
    backupId: string;
    replacementId: string;
    replacementKey: JsonWebKey;
    constructor(sign, backupId, jwk) {
        this.backupId = backupId;
        this.signature = sign;
        this.replacementId = jwk.kid;
        this.replacementKey = jwk;
    }
}

async function loadDelegations(): Promise<Array<Delegation>> {
    log.info("Loading delegations from JSON file");
    return new Promise<Array<Delegation>>(function (resolve, reject) {
        let xhr = new XMLHttpRequest();
        xhr.open("GET", chrome.extension.getURL('/recovery/delegation.json'), true);
        xhr.onload = async function () {
            let status = xhr.status;
            if (status == 200) {
                let rawDelegations = JSON.parse(this.response);
                let i;
                let del = new Array<Delegation>()
                for (i = 0; i < rawDelegations.length; ++i) {
                    let sign = rawDelegations[i].signature;
                    let bId = base64ToByteArray(rawDelegations[i].cred_id, true);
                    const encBId = byteArrayToBase64(bId, true);
                    del.push(new Delegation(sign, encBId, rawDelegations[i].public_key));
                }
                await resolve(del);
            } else {
                reject(status);
            }
        };
        xhr.send();
    });
}

async function parseJWK(jwk, usages): Promise<CryptoKey> {
    return window.crypto.subtle.importKey(
        "jwk",
        jwk,
        {
            name: "ECDSA",
            namedCurve: "P-256"
        },
        true,
        usages
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

    log.debug(`Storing ${identifier} keys`, pskJSON);

    return new Promise<void>(async (res, rej) => {
        chrome.storage.sync.set({ [identifier]: pskJSON }, () => {
            if (!!chrome.runtime.lastError) {
                log.warn(`Could not store ${identifier} keys`, pskJSON);
                rej(chrome.runtime.lastError);
            } else {
                res();
            }
        });
    });
}

async function storeDelegations(del: Array<Delegation>): Promise<void> {
    let delJSON = JSON.stringify(del);

    log.debug(`Storing ${DELEGATION}`, delJSON);

    return new Promise<void>(async (res, rej) => {
        chrome.storage.sync.set({ [DELEGATION]: delJSON }, () => {
            if (!!chrome.runtime.lastError) {
                log.warn(`Could not store ${DELEGATION}`, del);
                rej(chrome.runtime.lastError);
            } else {
                res();
            }
        });
    });
}

async function fetchPSKKeys(identifier: string, usages): Promise<Array<PSKKey>> {
        return new Promise<Array<PSKKey>>(async (res, rej) => {
            chrome.storage.sync.get(identifier, async (resp) => {
                if (!!chrome.runtime.lastError) {
                    log.warn(`Could not fetch ${identifier} keys`);
                    rej(chrome.runtime.lastError);
                    return;
                }

                let exportedKey = await JSON.parse(resp[identifier]);
                let pskKeys = new Array<PSKKey>();
                let i;
                for (i = 0; i < exportedKey.length; ++i) {
                    let parsedKey = await parseJWK(exportedKey[i].key, usages);
                    pskKeys.push(new PSKKey(parsedKey, exportedKey[i].id));
                }
                res(pskKeys);
            });
        });
}

async function fetchDelegations(): Promise<Array<Delegation>> {
    return new Promise<Array<Delegation>>(async (res, rej) => {
        chrome.storage.sync.get(DELEGATION, async (resp) => {
            if (!!chrome.runtime.lastError) {
                log.warn(`Could not fetch ${DELEGATION}`);
                rej(chrome.runtime.lastError);
                return;
            }

            let delegations = await JSON.parse(resp[DELEGATION]);
            res(delegations);
        });
    });
}

async function popPSKKey(identifier: string, usages): Promise<PSKKey> {
    let pskKeys = await fetchPSKKeys(identifier, usages);
    if (pskKeys.length == 0) {
        throw new Error(`No ${identifier} key available to pop`);
    }
    let key = pskKeys.pop();
    await storePSKKeys(identifier, pskKeys)
    log.info(`${pskKeys.length} ${identifier} keys left`);
    return key;
}

export async function popBackupKey(): Promise<BackupKey> {
    return popPSKKey(BACKUP, ['sign']);
}

export async function pskSetupExtensionOutput(backupKey: BackupKey): Promise<Uint8Array> {
    let compatibleKey = await getCompatibleKeyFromCryptoKey(backupKey.key);
    const coseKey = await compatibleKey.toCOSE(backupKey.key);
    let encodedKey = new Uint8Array(CBOR.encode(coseKey));

    log.debug(encodedKey);

    let extOutput = new Map([[PSK, encodedKey]]);
    return new Uint8Array(CBOR.encode(extOutput));
}

async function pskRecoveryExtensionOutput(recMsg: RecoveryMessage): Promise<Uint8Array> {
    let extOutput = new Map([[PSK, recMsg.encode()]]);
    return new Uint8Array(CBOR.encode(extOutput));
}

export async function createRecoveryKeys(n: number) {
    let rcvKeys = new Array<RecoveryKey>();
    let jwk = new Array<JsonWebKey>();
    let i;
    for (i = 0; i < n; ++i) {
        let keyPair = await window.crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: "P-256" },
            true,
            ['sign'],
        );
        let rk = new RecoveryKey(keyPair.privateKey)
        let expKey: any = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
        expKey.kid = rk.id;

        rcvKeys.push(rk);
        jwk.push(expKey);
    }

    await storePSKKeys(RECOVERY, rcvKeys);

    // Download recovery public keys as file
    let json = [JSON.stringify(jwk)];
    let blob1 = new Blob(json, { type: "text/plain;charset=utf-8" });
    let link = (window.URL ? URL : webkitURL).createObjectURL(blob1);
    let a = document.createElement("a");
    a.download = "recoveryKeys.json";
    a.href = link;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    log.debug("Downloading recovery keys completed");

}

async function getDelegation(credentialId: string): Promise<Delegation> {
    const del = await fetchDelegations();
    log.debug('Fetched delegations', del);
    const rec = del.filter(x => x.backupId === credentialId);
    return rec.length != 0 ? rec[0] : null;
}

async function getRecoveryKey(credentialId: string): Promise<RecoveryKey> {
    const rks = await fetchPSKKeys(RECOVERY, ['sign']);
    log.debug(rks);
    const rk = rks.filter(x => x.id === credentialId);
    return rk.length != 0 ? rk[0] : null;
}

function createId(): string{
    let enc =  new TextEncoder();
    let dt = new Date().getTime();
    const uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = (dt + Math.random()*16)%16 | 0;
        dt = Math.floor(dt/16);
        return (c=='x' ? r :(r&0x3|0x8)).toString(16);
    });
    return byteArrayToBase64(enc.encode(uuid), true);
}

class RecoveryOptions {
    recoveryKey: RecoveryKey;
    delegation: Delegation;

    constructor(rk: RecoveryKey, del: Delegation) {
        this.delegation = del;
        this.recoveryKey = rk;
    }
}

async function getRecoveryOptions(backupCredentialId: string): Promise<RecoveryOptions> {
    const del = await getDelegation(backupCredentialId);
    log.debug('Use delegation', del);
    const rk = await getRecoveryKey(del.replacementId);
    log.debug('Use recovery key', rk);
    return new RecoveryOptions(rk, del);
}


// This function is called when recovery is needed
export const recover = async (
    origin: string,
    publicKeyRequestOptions: PublicKeyCredentialRequestOptions,
    pin: string,
): Promise<Credential> => {
    if (!publicKeyRequestOptions.allowCredentials) {
        log.debug('No keys requested');
        return null;
    }

    //origin = 'http://localhost:9005'; // Given origin does not work!
    log.debug('origin', origin)

    // For now we will only worry about the first entry
    const requestedCredential = publicKeyRequestOptions.allowCredentials[0];
    const backupCredId: ArrayBuffer = requestedCredential.id as ArrayBuffer;
    const encBackupCredId = byteArrayToBase64(new Uint8Array(backupCredId), true);
    log.info('Started recovery for', encBackupCredId);

    const recOps = await getRecoveryOptions(encBackupCredId);
    log.debug('Recovery options', recOps);

    const rkPrv = await getCompatibleKeyFromCryptoKey(recOps.recoveryKey.key);
    log.debug('prv', rkPrv.privateKey);
    const rkPubRaw = await parseJWK(recOps.delegation.replacementKey, []);
    const rkPub = await getCompatibleKeyFromCryptoKey(rkPubRaw);
    log.debug('pub', rkPub.publicKey);

    const recMessage = new RecoveryMessage();
    await recMessage.init(recOps.delegation, rkPub, origin, publicKeyRequestOptions.challenge as ArrayBuffer);
    log.debug('Recovery message', recMessage);
    const extOutput = await pskRecoveryExtensionOutput(recMessage);

    await saveKey(recOps.recoveryKey.id, rkPrv.privateKey, pin);

    const clientData = await rkPrv.generateClientData(
        publicKeyRequestOptions.challenge as ArrayBuffer,
        {
            origin,
            tokenBinding: {
                status: 'not-supported',
            },
            type: 'webauthn.get',
        },
    );
    const clientDataJSON = base64ToByteArray(window.btoa(clientData));
    const clientDataHash = new Uint8Array(await window.crypto.subtle.digest('SHA-256', clientDataJSON));

    const rpID = publicKeyRequestOptions.rpId || getDomainFromOrigin(origin);

    const authenticatorData = await rkPrv.generateAuthenticatorData(rpID, 0, new Uint8Array(), new Uint8Array(extOutput));

    const concatData = new Uint8Array(authenticatorData.length + clientDataHash.length);
    concatData.set(authenticatorData);
    concatData.set(clientDataHash, authenticatorData.length);

    const signature = await rkPrv.sign(concatData);
    return { // ToDo Make getClientExtensionResults work
        id: recOps.recoveryKey.id,
        rawId: base64ToByteArray(recOps.recoveryKey.id, true),
        response: {
            authenticatorData: authenticatorData.buffer,
            clientDataJSON: clientDataJSON,
            signature: (new Uint8Array(signature)).buffer,
            userHandle: new ArrayBuffer(0), // This should be nullable
        },
        type: 'public-key',
    } as Credential;
};
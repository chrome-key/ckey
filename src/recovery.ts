import * as CBOR from 'cbor';
import {getLogger} from './logging';
import {getCompatibleKeyFromCryptoKey, ICOSECompatibleKey} from './crypto';
import {base64ToByteArray, byteArrayToBase64, getDomainFromOrigin} from './utils';
import {fetchExportContainer, saveExportContainer, saveKey} from './storage';

const log = getLogger('recovery');

export const PSK: string = 'psk'

export type ExportContainerType = string
const BACKUP: ExportContainerType = 'backup'
const RECOVERY: ExportContainerType = 'recovery'
const DELEGATION: ExportContainerType = 'delegation'

export async function syncBackupKeys (content) {
    const jwk = JSON.parse(content);
    let i;
    const container = new Array<ExportContainer>();
    for (i = 0; i < jwk.length; ++i) {
        const parsedKey = await parseJWK(jwk[i], []);
        const id = base64ToByteArray(jwk[i].kid, true);
        const encId = byteArrayToBase64(id, true);
        const bckpKey = new BackupKey(parsedKey, encId);
        const expBckpKey = await bckpKey.export();
        container.push(expBckpKey);
    }
    log.debug('Loaded backup keys', container);

    await saveExportContainer(BACKUP, container);
}

export async function syncDelegation (content) {
    const rawDelegations = JSON.parse(content);
    let i;
    const container = new Array<ExportContainer>();
    for (i = 0; i < rawDelegations.length; ++i) {
        const sign = rawDelegations[i].sign;
        const srcCredId = base64ToByteArray(rawDelegations[i].src_cred_id, true);
        const encSrcCredId = byteArrayToBase64(srcCredId, true);
        const del = new Delegation(sign, encSrcCredId, rawDelegations[i].pub_rk);
        container.push(del.export());
    }
    log.debug("Loaded delegation", container);
    await saveExportContainer(DELEGATION, container);
}

export class ExportContainer {
    id: string;
    payload: string;

    constructor(id: string, payload: string) {
        this.id = id;
        this.payload = payload;
    }
}

export class BackupKey {
    key: CryptoKey;
    id: string;

    constructor(key: CryptoKey, id: string) {
        this.key = key;
        this.id = id;
    }

    async export(): Promise<ExportContainer> {
        const jwk = await window.crypto.subtle.exportKey("jwk", this.key);
        const encJWK = JSON.stringify(jwk);
        return new ExportContainer(this.id, encJWK);
    }
    static async import(kx: ExportContainer): Promise<BackupKey> {
        const rawKey = JSON.parse(kx.payload);
        const key = await parseJWK(rawKey, []);
        return new BackupKey(key, kx.id);
    }

    static async get(): Promise<BackupKey> {
        const container = await fetchExportContainer(BACKUP);
        if (container.length == 0) {
            throw new Error(`No backup key available`);
        }
        const key = container.pop();
        await saveExportContainer(BACKUP, container);
        log.debug(`${container.length} backup keys left`);

        return await BackupKey.import(key);
    }
}

export class RecoveryKey {
    key: CryptoKey;
    id: string;
    backupKey: BackupKey;

    constructor(key: CryptoKey, backupKey: BackupKey) {
        this.id = backupKey.id;
        this.backupKey = backupKey;
        this.key = key;
    }

    async export(): Promise<ExportContainer> {
        const parsedKey = await window.crypto.subtle.exportKey("jwk", this.key);
        const expBackupKey = await this.backupKey.export();
        const rawJSON = {parsedKey: parsedKey, parsedBackupKey: expBackupKey};

        return new ExportContainer(this.id, JSON.stringify(rawJSON));
    }

    static async import(kx: ExportContainer): Promise<RecoveryKey> {
        const json = JSON.parse(kx.payload);
        const key = await parseJWK(json.parsedKey, ['sign']);
        const backupKey = await BackupKey.import(json.parsedBackupKey);

        return new RecoveryKey(key, backupKey);
    }

    static async generate(n: number) {
        const jwk = new Array<JsonWebKey>();
        const container = new Array<ExportContainer>();
        let i;
        for (i = 0; i < n; ++i) {
            const keyPair = await window.crypto.subtle.generateKey(
                { name: 'ECDSA', namedCurve: "P-256" },
                true,
                ['sign'],
            );
            const bckKey = await BackupKey.get();
            const rk = new RecoveryKey(keyPair.privateKey, bckKey);
            const exportRk = await rk.export();
            const pubJWK: any = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
            pubJWK.kid = rk.id;

            container.push(exportRk);
            jwk.push(pubJWK);
        }

        await saveExportContainer(RECOVERY, container);

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
}

class Delegation {
    sign: string;
    srcCredId: string;
    rkId: string;
    pubRK: JsonWebKey;
    constructor(sign, srcCredId, jwk) {
        this.srcCredId = srcCredId;
        this.sign = sign;
        this.rkId = jwk.kid;
        this.pubRK = jwk;
    }

    export(): ExportContainer {
        return new ExportContainer(this.srcCredId,  JSON.stringify(this));
    }
    static import(kx: ExportContainer): Delegation {
        return JSON.parse(kx.payload);
    }

    static async getById(srcCredId: string): Promise<Delegation> {
        const container = await fetchExportContainer(DELEGATION);
        log.debug('Fetched delegations', container);
        const del = container.filter(x => x.id === srcCredId);
        return del.length != 0 ? (Delegation.import(del[0])) : null;
    }
}

class RecoveryMessage {
    srcCredId: string;
    delSign: Uint8Array;
    pubRK: Uint8Array;
    attestationObject: Uint8Array;
    clientDataJSON: Uint8Array;

    constructor() {
        // Dummy
    }

    async init(delegation: Delegation, rkPub: ICOSECompatibleKey, origin: string, challenge: ArrayBuffer) {
        this.srcCredId = delegation.srcCredId;
        this.delSign = base64ToByteArray(delegation.sign, true);

        // Create attestation object for new key
        const recoveryCredId = base64ToByteArray(delegation.rkId, true);

        // ToDo New Credential should also contain backup key
        const authData = await rkPub.generateAuthenticatorData(origin, 0, recoveryCredId, null);

        const coseKey = await rkPub.toCOSE(rkPub.publicKey);
        this.pubRK = new Uint8Array(CBOR.encode(coseKey));

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
            delSign: byteArrayToBase64(this.delSign, true),
            srcCredId: this.srcCredId,
            authAttData: {
                clientDataJSON: this.clientDataJSON,
                attestationObject: this.attestationObject
            },
        }).buffer;
    }
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

export async function createPSKSetupExtensionOutput(backupKey: BackupKey): Promise<Uint8Array> {
    let compatibleKey = await getCompatibleKeyFromCryptoKey(backupKey.key);
    const coseKey = await compatibleKey.toCOSE(backupKey.key);
    let encodedKey = new Uint8Array(CBOR.encode(coseKey));

    let extOutput = new Map([[PSK, encodedKey]]);
    return new Uint8Array(CBOR.encode(extOutput));
}

async function createPSKRecoveryExtensionOutput(recMsg: RecoveryMessage): Promise<Uint8Array> {
    let extOutput = new Map([[PSK, recMsg.encode()]]);
    return new Uint8Array(CBOR.encode(extOutput));
}



async function getRecoveryKey(id: string): Promise<RecoveryKey> {
    const container = await fetchExportContainer(RECOVERY);
    log.debug(container);
    const rk = container.filter(x => x.id === id);
    return rk.length != 0 ? (await RecoveryKey.import(rk[0])) : null;
}

class RecoveryOptions {
    rk: RecoveryKey;
    del: Delegation;

    constructor(rk: RecoveryKey, del: Delegation) {
        this.del = del;
        this.rk = rk;
    }
}

async function getRecoveryOptions(srcCredId: string): Promise<RecoveryOptions> {
    const del = await Delegation.getById(srcCredId);
    log.debug('Use delegation', del);
    const rk = await getRecoveryKey(del.rkId);
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

    // For now we will only worry about the first entry
    const requestedCredential = publicKeyRequestOptions.allowCredentials[0];
    const srcCredId: ArrayBuffer = requestedCredential.id as ArrayBuffer;
    const encSrcCredId = byteArrayToBase64(new Uint8Array(srcCredId), true);
    log.info('Started recovery for', encSrcCredId);

    const recOps = await getRecoveryOptions(encSrcCredId);
    log.debug('Recovery options', recOps);

    const rkId = base64ToByteArray(recOps.rk.id, true);
    const encRkId = byteArrayToBase64(rkId, true);

    const prvRK = await getCompatibleKeyFromCryptoKey(recOps.rk.key);
    const rawPubRK = await parseJWK(recOps.del.pubRK, []);
    const pubRK = await getCompatibleKeyFromCryptoKey(rawPubRK);

    const recMessage = new RecoveryMessage();
    await recMessage.init(recOps.del, pubRK, origin, publicKeyRequestOptions.challenge as ArrayBuffer);
    log.debug('Recovery message', recMessage);
    const extOutput = await createPSKRecoveryExtensionOutput(recMessage);

    await saveKey(encRkId, prvRK.privateKey, pin);

    const clientData = await prvRK.generateClientData(
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

    const authenticatorData = await prvRK.generateAuthenticatorData(rpID, 0, new Uint8Array(), new Uint8Array(extOutput));

    const concatData = new Uint8Array(authenticatorData.length + clientDataHash.length);
    concatData.set(authenticatorData);
    concatData.set(clientDataHash, authenticatorData.length);

    const signature = await prvRK.sign(concatData);

    return { // ToDo Make getClientExtensionResults work
        id: encRkId,
        rawId: rkId,
        response: {
            authenticatorData: authenticatorData.buffer,
            clientDataJSON: clientDataJSON,
            signature: (new Uint8Array(signature)).buffer,
            userHandle: new ArrayBuffer(0), // This should be nullable
        },
        type: 'public-key',
    } as Credential;
};
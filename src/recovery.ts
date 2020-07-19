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
        const sign = rawDelegations[i].signature;
        const bId = base64ToByteArray(rawDelegations[i].cred_id, true);
        const encBId = byteArrayToBase64(bId, true);
        const del = new Delegation(sign, encBId, rawDelegations[i].public_key);
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

    export(): ExportContainer {
        return new ExportContainer(this.backupId,  JSON.stringify(this));
    }
    static import(kx: ExportContainer): Delegation {
        return JSON.parse(kx.payload);
    }
}

class RecoveryMessage { // ToDo Clean up
    backupCredId: string;
    delegationSignature: Uint8Array;
    pubKey: Uint8Array;
    attestationObject: Uint8Array;
    clientDataJSON: Uint8Array;

    constructor() {
        // Dummy
    }

    // ToDo Irgendwie ist der PubKey der in der RP registriert wird, nicht der PuBkey der im Plugin genutzt wird
    async init(delegation: Delegation, rkPub: ICOSECompatibleKey, origin: string, challenge: ArrayBuffer) {
        this.backupCredId = delegation.backupId;
        this.delegationSignature = base64ToByteArray(delegation.signature, true);

        // Create attestation object for new key
        const recoveryCredId = base64ToByteArray(delegation.replacementId, true); // ToDo Irgenwie wird jetzt true gebraucht, obwohl vorher doch auch Base64 war? --> Das macht vlt attestation kapput?

        // ToDo New Credential should also contain recovery key
        log.debug('init: delegation.replacementId', delegation.replacementId);
        const authData = await rkPub.generateAuthenticatorData(origin, 0, recoveryCredId, null);
        log.debug('AuthData of recovery message', authData);

        const coseKey = await rkPub.toCOSE(rkPub.publicKey);
        log.debug('init: coseKey', rkPub.publicKey);
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

export async function getBackupKey(): Promise<BackupKey> {
    const container = await fetchExportContainer(BACKUP);
    if (container.length == 0) {
        throw new Error(`No backup key available`);
    }
    const key = container.pop();
    await saveExportContainer(BACKUP, container);
    log.debug(`${container.length} backup keys left`);

    return await BackupKey.import(key);
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
    const jwk = new Array<JsonWebKey>();
    const container = new Array<ExportContainer>();
    let i;
    for (i = 0; i < n; ++i) {
        const keyPair = await window.crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: "P-256" },
            true,
            ['sign'],
        );
        const bckKey = await getBackupKey();
        const rk = new RecoveryKey(keyPair.privateKey, bckKey);
        const exportRk = await rk.export();
        const keyJWK: any = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
        keyJWK.kid = rk.id;

        container.push(exportRk);
        jwk.push(keyJWK);
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

async function getDelegation(credentialId: string): Promise<Delegation> {
    const container = await fetchExportContainer(DELEGATION);
    log.debug('Fetched delegations', container);
    const del = container.filter(x => x.id === credentialId);
    return del.length != 0 ? (Delegation.import(del[0])) : null;
}

async function getRecoveryKey(credentialId: string): Promise<RecoveryKey> {
    const container = await fetchExportContainer(RECOVERY);
    log.debug(container);
    const rk = container.filter(x => x.id === credentialId);
    return rk.length != 0 ? (await RecoveryKey.import(rk[0])) : null;
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

    // For now we will only worry about the first entry
    const requestedCredential = publicKeyRequestOptions.allowCredentials[0];
    const backupCredId: ArrayBuffer = requestedCredential.id as ArrayBuffer;
    const encBackupCredId = byteArrayToBase64(new Uint8Array(backupCredId), true);
    log.info('Started recovery for', encBackupCredId);

    const recOps = await getRecoveryOptions(encBackupCredId);
    log.debug('Recovery options', recOps);

    const credId = base64ToByteArray(recOps.recoveryKey.id, true);
    const encCredId = byteArrayToBase64(credId, true);

    const rkPrv = await getCompatibleKeyFromCryptoKey(recOps.recoveryKey.key);
    const rkPubRaw = await parseJWK(recOps.delegation.replacementKey, []);
    const rkPub = await getCompatibleKeyFromCryptoKey(rkPubRaw);

    const recMessage = new RecoveryMessage();
    await recMessage.init(recOps.delegation, rkPub, origin, publicKeyRequestOptions.challenge as ArrayBuffer);
    log.debug('Recovery message', recMessage);
    const extOutput = await pskRecoveryExtensionOutput(recMessage);

    await saveKey(encCredId, rkPrv.privateKey, pin);

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
    log.debug(clientData);

    return { // ToDo Make getClientExtensionResults work
        id: encCredId,
        rawId: credId,
        response: {
            authenticatorData: authenticatorData.buffer,
            clientDataJSON: clientDataJSON,
            signature: (new Uint8Array(signature)).buffer,
            userHandle: new ArrayBuffer(0), // This should be nullable
        },
        type: 'public-key',
    } as Credential;
};
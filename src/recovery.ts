import * as axios from 'axios';
import * as CBOR from 'cbor';

import {base64ToByteArray, byteArrayToBase64, getDomainFromOrigin, padString} from './utils';

import {fetchExportContainer, saveExportContainer, PublicKeyCredentialSource} from './storage';

import {getCompatibleKeyFromCryptoKey} from './crypto';

import {getLogger} from './logging';

const log = getLogger('recovery');

export const PSK: string = 'psk';

const BACKUP_DEVICE_URL = 'bd_url';

export async function setBackupDeviceBaseUrl(url: string) {
    await saveExportContainer(CONFIG, new Array(new ExportContainer(BACKUP_DEVICE_URL, url)));
}

export async function getBackupDeviceBaseUrl(): Promise<string> {
    const ct = await fetchExportContainer(CONFIG).catch(_ => Array());
    const config = ct.filter((c) => c.id === BACKUP_DEVICE_URL);
    return config.length !== 0 ? config[0].payload : 'http://localhost:8005';
}

export type ExportContainerType = string;
const BACKUP: ExportContainerType = 'backup';
const RECOVERY: ExportContainerType = 'recovery';
const DELEGATION: ExportContainerType = 'delegation';
const CONFIG: ExportContainerType = 'config';

export async function pskSetup() {
    const authId = prompt('Please enter a name for your authenticator', 'MyAuth');
    const keyAmount: number = +prompt('How many backup keys should be created?', '5');

    const url = await getBackupDeviceBaseUrl();

    await axios.default.post(url  + '/setup', {authId, keyAmount})
        .then(async function(response) {
            log.debug(response);
            const stpRsp = response.data;
            let i;
            const container = new Array<ExportContainer>();
            for (i = 0; i < stpRsp.length; ++i) {
                const jwk = stpRsp[i].jwk;
                const attObj = stpRsp[i].attObj;
                const parsedKey = await parseJWK(jwk, []);
                const id = base64ToByteArray(jwk.kid, true);
                const encId = byteArrayToBase64(id, true);
                const bckpKey = new BackupKey(parsedKey, encId, attObj);
                const expBckpKey = await bckpKey.export();
                container.push(expBckpKey);
            }
            log.debug('Loaded backup keys', container);

            await saveExportContainer(BACKUP, container);
        })
        .catch(function(error) {
            log.error(error);
        });
}

export async function pskRecovery() {
    const authId = prompt('Which authenticator you want to replace?', 'MyAuth');

    const url = await getBackupDeviceBaseUrl();

    await axios.default.get(url  + '/recovery?authId=' + authId)
        .then(async function(response1) {
            log.debug(response1);
            const keyAmount = response1.data.keyAmount;

            const rkData = await RecoveryKey.generate(keyAmount);

            await axios.default.post(url  + '/recovery', {rkData, authId})
                .then(async function(response2) {
                    log.debug(response2);
                    const rawDelegations = response2.data;

                    let i;
                    const container = new Array<ExportContainer>();
                    for (i = 0; i < rawDelegations.length; ++i) {
                        const sign = base64ToByteArray(rawDelegations[i].sign, true);
                        const encSign = byteArrayToBase64(sign, true);
                        const srcCredId = base64ToByteArray(rawDelegations[i].srcCredId, true);
                        const encSrcCredId = byteArrayToBase64(srcCredId, true);
                        const dstCredId = base64ToByteArray(rawDelegations[i].dstCredId, true);
                        const encDstCredId = byteArrayToBase64(dstCredId, true);
                        const del = new Delegation(encSign, encSrcCredId, encDstCredId);
                        container.push(del.export());
                    }
                    log.debug('Loaded delegation', container);
                    await saveExportContainer(DELEGATION, container);
                })
                .catch(function(error) {
                    log.error(error);
                });
        })
        .catch(function(error) {
            log.error(error);
        });
}

export class ExportContainer {
    public id: string;
    public payload: string;

    constructor(id: string, payload: string) {
        this.id = id;
        this.payload = payload;
    }
}

export class BackupKey {
    public static async import(kx: ExportContainer): Promise<BackupKey> {
        const json = JSON.parse(kx.payload);
        const key = await parseJWK(json.parsedKey, []);
        return new BackupKey(key, kx.id, json.attObj);
    }

    public static async get(): Promise<BackupKey> {
        const container = await fetchExportContainer(BACKUP);
        if (container.length === 0) {
            throw new Error(`No backup key available`);
        }
        const key = container.pop();
        await saveExportContainer(BACKUP, container);
        log.debug(`${container.length} backup keys left`);

        return await BackupKey.import(key);
    }

    public key: CryptoKey;
    public attObj: string;
    public id: string;

    constructor(key: CryptoKey, id: string, attObj: string) {
        this.key = key;
        this.id = id;
        this.attObj = attObj;
    }

    public async export(): Promise<ExportContainer> {
        const jwk = await window.crypto.subtle.exportKey('jwk', this.key);
        const rawJSON = {parsedKey: jwk, attObj: this.attObj};
        return new ExportContainer(this.id, JSON.stringify(rawJSON));
    }
}

export class RecoveryKey {
    public static async import(kx: ExportContainer): Promise<RecoveryKey> {
        const json = JSON.parse(kx.payload);
        const key = await parseJWK(json.parsedKey, ['sign']);
        const attObj = base64ToByteArray(json.parsedAttObj, true);

        return new RecoveryKey(kx.id, key, attObj);
    }

    public static async generate(n: number): Promise<ExportContainer[]> {
        const delSetup = new Array<ExportContainer>();
        const container = new Array<ExportContainer>();
        let i;
        for (i = 0; i < n; ++i) {
            const keyPair = await window.crypto.subtle.generateKey(
                { name: 'ECDSA', namedCurve: 'P-256' },
                true,
                ['sign'],
            );

            const bckKey = await BackupKey.get();
            const pubRk = await getCompatibleKeyFromCryptoKey(keyPair.publicKey);
            const pskSetup = await createPSKSetupExtensionOutput(bckKey);
            const authData = await pubRk.generateAuthenticatorData('', 0, base64ToByteArray(bckKey.id, true), pskSetup);
            const attObj = CBOR.encodeCanonical({
                attStmt: new Map(),
                authData,
                fmt: 'none',
            });

            const exportRk = await (new RecoveryKey(bckKey.id, keyPair.privateKey, attObj)).export();
            container.push(exportRk);

            delSetup.push(new ExportContainer(exportRk.id, padString(byteArrayToBase64(attObj, true))));
        }

        await saveExportContainer(RECOVERY, container);

        return delSetup;
    }

    public key: CryptoKey;
    public id: string;
    public attObj: Uint8Array;

    constructor(id: string, key: CryptoKey, attObj: Uint8Array) {
        this.id = id;
        this.key = key;
        this.attObj = attObj;
    }

    public async export(): Promise<ExportContainer> {
        const parsedKey = await window.crypto.subtle.exportKey('jwk', this.key);
        const parsedAttObj = byteArrayToBase64(this.attObj, true);
        const rawJSON = {parsedKey, parsedAttObj};

        return new ExportContainer(this.id, JSON.stringify(rawJSON));
    }
}

class Delegation {
    public static import(kx: ExportContainer): Delegation {
        return JSON.parse(kx.payload);
    }

    public static async getById(srcCredId: string): Promise<Delegation> {
        const container = await fetchExportContainer(DELEGATION);
        log.debug('Fetched delegations', container);
        const del = container.filter((x) => x.id === srcCredId);
        return del.length !== 0 ? (Delegation.import(del[0])) : null;
    }

    public sign: string;
    public srcCredId: string;
    public dstCredId: string;

    constructor(sign, srcCredId, dstCredId) {
        this.srcCredId = srcCredId;
        this.sign = sign;
        this.dstCredId = dstCredId;
    }

    public export(): ExportContainer {
        return new ExportContainer(this.srcCredId,  JSON.stringify(this));
    }
}

class RecoveryMessage {
    public del: Delegation;
    public rk: RecoveryKey;

    constructor(delegation: Delegation, rk: RecoveryKey) {
        this.del = delegation;
        this.rk = rk;
    }

    public encode(): ArrayBuffer {
        return CBOR.encodeCanonical({
            attestationObject: this.rk.attObj,
            delSign: this.del.sign,
            srcCredId: this.del.srcCredId,
        }).buffer;
    }
}

async function parseJWK(jwk, usages): Promise<CryptoKey> {
    return window.crypto.subtle.importKey(
        'jwk',
        jwk,
        {
            name: 'ECDSA',
            namedCurve: 'P-256',
        },
        true,
        usages,
    );
}

export async function createPSKSetupExtensionOutput(backupKey: BackupKey): Promise<Uint8Array> {
    const stpMsg = CBOR.encodeCanonical({attObj: base64ToByteArray(backupKey.attObj, true)});
    const extOutput = new Map([[PSK, stpMsg]]);
    return new Uint8Array(CBOR.encodeCanonical(extOutput));
}

async function createPSKRecoveryExtensionOutput(recMsg: RecoveryMessage): Promise<Uint8Array> {
    const extOutput = new Map([[PSK, recMsg.encode()]]);
    return new Uint8Array(CBOR.encodeCanonical(extOutput));
}

async function getRecoveryKey(id: string): Promise<RecoveryKey> {
    const container = await fetchExportContainer(RECOVERY);
    log.debug(container);
    const rk = container.filter((x) => x.id === id);
    return rk.length !== 0 ? (await RecoveryKey.import(rk[0])) : null;
}

class RecoveryOptions {
    public rk: RecoveryKey;
    public del: Delegation;

    constructor(rk: RecoveryKey, del: Delegation) {
        this.del = del;
        this.rk = rk;
    }
}

async function getRecoveryOptions(srcCredId: string): Promise<RecoveryOptions> {
    const del = await Delegation.getById(srcCredId);
    log.debug('Use delegation', del);
    if (del === null) {
        return null;
    }
    const rk = await getRecoveryKey(del.dstCredId);
    log.debug('Use recovery key', rk);
    if (rk === null) {
        return null;
    }
    return new RecoveryOptions(rk, del);
}

export const recover = async (
    origin: string,
    publicKeyRequestOptions: PublicKeyCredentialRequestOptions,
    pin: string,
): Promise<Credential> => {
    if (!publicKeyRequestOptions.allowCredentials) {
        log.debug('No keys requested');
        return null;
    }

    let srcCredId: ArrayBuffer;
    let encSrcCredId;
    let i;
    let recOps;
    let requestedCredential;
    for (i = 0; i < publicKeyRequestOptions.allowCredentials.length; i++) {
        requestedCredential = publicKeyRequestOptions.allowCredentials[i];
        srcCredId = requestedCredential.id as ArrayBuffer;
        encSrcCredId = byteArrayToBase64(new Uint8Array(srcCredId), true);

        recOps = await getRecoveryOptions(encSrcCredId);

        if (recOps !== null) {
            break;
        }
    }
    if (!recOps) {
        throw new Error(`no recovery options available for credential with id ${JSON.stringify(publicKeyRequestOptions.allowCredentials)}`);
    }

    log.info('Started recovery for', encSrcCredId);
    log.debug('Recovery options', recOps);

    const rkId = base64ToByteArray(recOps.rk.id, true);
    const encRkId = byteArrayToBase64(rkId, true);

    const rkPrv = await getCompatibleKeyFromCryptoKey(recOps.rk.key);

    const recMessage = new RecoveryMessage(recOps.del, recOps.rk);
    log.debug('Recovery message', recMessage);
    const extOutput = await createPSKRecoveryExtensionOutput(recMessage);

    const rpID = publicKeyRequestOptions.rpId || getDomainFromOrigin(origin);

    const publicKeyCredentialSource = new PublicKeyCredentialSource(encRkId, rkPrv.privateKey, rpID, null);
    await publicKeyCredentialSource.store( pin);

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

    const authenticatorData = await rkPrv.generateAuthenticatorData(rpID, 0, new Uint8Array(),
        new Uint8Array(extOutput));

    const concatData = new Uint8Array(authenticatorData.length + clientDataHash.length);
    concatData.set(authenticatorData);
    concatData.set(clientDataHash, authenticatorData.length);

    const signature = await rkPrv.sign(concatData);

    return {
        getClientExtensionResults: () => ({}),
        id: encRkId,
        rawId: rkId,
        response: {
            authenticatorData: authenticatorData.buffer,
            clientDataJSON,
            signature: (new Uint8Array(signature)).buffer,
            userHandle: new ArrayBuffer(0), // This should be nullable
        },
        type: 'public-key',
    } as PublicKeyCredential;
};

import * as CBOR from 'cbor';
import {getLogger} from './logging';
import {getCompatibleKeyFromCryptoKey} from './crypto';
import {base64ToByteArray, byteArrayToBase64, getDomainFromOrigin, padString} from './utils';
import {fetchExportContainer, saveExportContainer, saveKey} from './storage';
import * as axios from "axios";

const log = getLogger('recovery');

export const PSK: string = 'psk'

export const BackupDeviceBaseUrl = 'http://localhost:8005' // ToDo Load from a config file

export type ExportContainerType = string
const BACKUP: ExportContainerType = 'backup'
const RECOVERY: ExportContainerType = 'recovery'
const DELEGATION: ExportContainerType = 'delegation'

export async function pskSetup () {
    const authId = prompt("Please enter a name for your authenticator", "MyAuth");
    const keyAmount: number = +prompt("How many backup keys should be created?", "5");

    await axios.default.post(BackupDeviceBaseUrl  + '/setup', {authId: authId, keyAmount: keyAmount})
        .then(async function (response) {
            log.debug(response)
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
        .catch(function (error) {
            log.error(error);
        })
}

export async function pskRecovery () {
    const authId = prompt("Which authenticator you want to replace?", "MyAuth");

    await axios.default.get(BackupDeviceBaseUrl  + '/recovery?authId=' + authId)
        .then(async function (response1) {
            log.debug(response1);
            const keyAmount = response1.data.keyAmount;

            const rkData = await RecoveryKey.generate(keyAmount);

            await axios.default.post(BackupDeviceBaseUrl  + '/recovery', {rkData: rkData, authId: authId})
                .then(async function (response2) {
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
                    log.debug("Loaded delegation", container);
                    await saveExportContainer(DELEGATION, container);
                })
                .catch(function (error) {
                    log.error(error);
                })
        })
        .catch(function (error) {
            log.error(error);
        })
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
    attObj: string;
    id: string;

    constructor(key: CryptoKey, id: string, attObj: string) {
        this.key = key;
        this.id = id;
        this.attObj = attObj;
    }

    async export(): Promise<ExportContainer> {
        const jwk = await window.crypto.subtle.exportKey("jwk", this.key);
        const rawJSON = {parsedKey: jwk, attObj: this.attObj};
        return new ExportContainer(this.id, JSON.stringify(rawJSON));
    }
    static async import(kx: ExportContainer): Promise<BackupKey> {
        const json = JSON.parse(kx.payload);
        const key = await parseJWK(json.parsedKey, []);
        return new BackupKey(key, kx.id, json.attObj);
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
    attObj: Uint8Array;

    constructor(id: string, key: CryptoKey, attObj: Uint8Array) {
        this.id = id;
        this.key = key;
        this.attObj = attObj;
    }

    async export(): Promise<ExportContainer> {
        const parsedKey = await window.crypto.subtle.exportKey("jwk", this.key);
        const parsedAttObj = byteArrayToBase64(this.attObj, true);
        const rawJSON = {parsedKey: parsedKey, parsedAttObj: parsedAttObj};

        return new ExportContainer(this.id, JSON.stringify(rawJSON));
    }

    static async import(kx: ExportContainer): Promise<RecoveryKey> {
        const json = JSON.parse(kx.payload);
        const key = await parseJWK(json.parsedKey, ['sign']);
        const attObj = base64ToByteArray(json.parsedAttObj, true);

        return new RecoveryKey(kx.id, key, attObj);
    }

    static async generate(n: number): Promise<Array<ExportContainer>> {
        const delSetup = new Array<ExportContainer>();
        const container = new Array<ExportContainer>();
        let i;
        for (i = 0; i < n; ++i) {
            const keyPair = await window.crypto.subtle.generateKey(
                { name: 'ECDSA', namedCurve: "P-256" },
                true,
                ['sign'],
            );

            const bckKey = await BackupKey.get();
            const pubRk = await getCompatibleKeyFromCryptoKey(keyPair.publicKey);
            const pskSetup = await createPSKSetupExtensionOutput(bckKey);
            const authData = await pubRk.generateAuthenticatorData("", 0, base64ToByteArray(bckKey.id, true), pskSetup);
            const attObj = CBOR.encodeCanonical({
                attStmt: new Map(),
                authData: authData,
                fmt: 'none',
            });

            const exportRk = await (new RecoveryKey(bckKey.id, keyPair.privateKey, attObj)).export();
            container.push(exportRk);

            delSetup.push(new ExportContainer(exportRk.id, padString(byteArrayToBase64(attObj, true))));
        }

        await saveExportContainer(RECOVERY, container);

        return delSetup;
    }
}

class Delegation {
    sign: string;
    srcCredId: string;
    dstCredId: string;
    constructor(sign, srcCredId, dstCredId) {
        this.srcCredId = srcCredId;
        this.sign = sign;
        this.dstCredId = dstCredId;
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
    del: Delegation;
    rk: RecoveryKey;

    constructor(delegation: Delegation, rk: RecoveryKey) {
        this.del = delegation;
        this.rk = rk;
    }

    encode(): ArrayBuffer {
        return CBOR.encodeCanonical({
            delSign: this.del.sign,
            srcCredId: this.del.srcCredId,
            attestationObject: this.rk.attObj
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
    let stpMsg = CBOR.encodeCanonical({attObj: base64ToByteArray(backupKey.attObj, true)});
    let extOutput = new Map([[PSK, stpMsg]]);
    return new Uint8Array(CBOR.encodeCanonical(extOutput));
}

async function createPSKRecoveryExtensionOutput(recMsg: RecoveryMessage): Promise<Uint8Array> {
    let extOutput = new Map([[PSK, recMsg.encode()]]);
    return new Uint8Array(CBOR.encodeCanonical(extOutput));
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
    const rk = await getRecoveryKey(del.dstCredId);
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

    const rkPrv = await getCompatibleKeyFromCryptoKey(recOps.rk.key);

    const recMessage = new RecoveryMessage(recOps.del, recOps.rk);
    log.debug('Recovery message', recMessage);
    const extOutput = await createPSKRecoveryExtensionOutput(recMessage);

    await saveKey(encRkId, rkPrv.privateKey, pin);

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

    return {
        getClientExtensionResults: () => ({}),
        id: encRkId,
        rawId: rkId,
        response: {
            authenticatorData: authenticatorData.buffer,
            clientDataJSON: clientDataJSON,
            signature: (new Uint8Array(signature)).buffer,
            userHandle: new ArrayBuffer(0), // This should be nullable
        },
        type: 'public-key',
    } as PublicKeyCredential;
};
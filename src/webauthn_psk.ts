import * as axios from 'axios';
import * as CBOR from 'cbor';

import {PSKStorage} from "./webauth_storage";
import {getLogger} from "./logging";
import {base64ToByteArray, byteArrayToBase64} from "./utils";
import {ECDSA, ICOSECompatibleKey} from "./webauthn_crypto";
import {getAttestationCertificate} from "./webauthn_attestation";

const log = getLogger('webauthn_psk');

export class BackupKey {
    public credentialId: string;
    public bdAttObj: string; // base64 URL with padding

    constructor(credId: string, attObj: string) {
        this.credentialId = credId;
        this.bdAttObj = attObj;
    }

    static async popBackupKey(): Promise<BackupKey> {
        const backupKeys = await PSKStorage.loadBackupKeys();
        if (backupKeys.length == 0) {
            throw new Error('No backup keys available');
        }
        const backupKey = backupKeys.pop();
        log.debug('Pop backup key', backupKey);
        await PSKStorage.storeBackupKeys(backupKeys, true);

        return backupKey;
    }
}

export class RecoveryKey {
    public credentialId: string
    public pubKey: CryptoKey
    public privKey: CryptoKey
    public delegationSignature: string

    constructor(credId: string, pubKey: CryptoKey, privKey: CryptoKey, sign: string) {
        this.credentialId = credId;
        this.pubKey = pubKey;
        this.privKey = privKey;
        this.delegationSignature = sign;
    }
}

export class PSK {
    public static async bdDeviceUrl(): Promise<string> {
        return await PSKStorage.getBDEndpoint();
    }

    public static async setOptions(url: string): Promise<void> {
        return await PSKStorage.setBDEndpoint(url);
    }

    public static async setup(): Promise<void> {
        const bdEndpoint = await PSKStorage.getBDEndpoint();
        const authAlias = prompt('Please enter an alias name for your authenticator', 'MyAuth');
        const keyAmount: number = +prompt('How many backup keys should be created?', '5');

        return await axios.default.post(bdEndpoint  + '/setup', {authAlias, keyAmount})
            .then(async function(response) {
                log.debug(response);
                const setupResponse = response.data;
                const backupKeys = new Array<BackupKey>();
                for (let i = 0; i < setupResponse.length; ++i) {
                    const backupKey = new BackupKey(setupResponse[i].credId, setupResponse[i].attObj);
                    backupKeys.push(backupKey);
                }
                log.debug('Loaded backup keys', backupKeys);

                await PSKStorage.storeBackupKeys(backupKeys);
            });
    }

    public static async recoverySetup(): Promise<void> {

        const authAlias = prompt('Which authenticator you want to recover?', 'MyAuth');
        const bdEndpoint = await PSKStorage.getBDEndpoint();

        return await axios.default.get(bdEndpoint  + '/recovery?authAlias=' + authAlias)
            .then(async function(initResponse) {
                log.debug(initResponse);
                const keyAmount = initResponse.data.keyAmount;

                let rawRecKeys = new Array<[string, CryptoKeyPair]>()
                let replacementKeys = []
                for (let i = 0; i < keyAmount; i++) {
                    const keyPair = await window.crypto.subtle.generateKey(
                        {name: 'ECDSA', namedCurve: 'P-256'},
                        true,
                        ['sign'],
                    );
                    rawRecKeys.push([i.toString(), keyPair]);

                    // Prepare delegation request
                    const pubKey = await ECDSA.fromKey(keyPair.publicKey);
                    const cosePubKey = await pubKey.toCOSE(pubKey.publicKey);
                    const encodedPubKey = new Uint8Array(CBOR.encodeCanonical(cosePubKey));
                    replacementKeys.push({keyId: i.toString(), replacementPubKey: byteArrayToBase64(encodedPubKey, true)});
                }

                let attCert = byteArrayToBase64(getAttestationCertificate(), true);

                await axios.default.post(bdEndpoint + '/recovery?authAlias=' + authAlias, {
                    repKeys: replacementKeys,
                    attCert
                })
                    .then(async function (delResponse) {
                        const rawDelegations = delResponse.data;

                        let recoveryKeys = new Array<RecoveryKey>()

                        for (let i = 0; i < rawDelegations.length; ++i) {
                            const sign = rawDelegations[i].sign;
                            const credId = rawDelegations[i].credId;
                            const keyId = rawDelegations[i].keyId;

                            log.debug(rawDelegations[i]);

                            const keyPair = rawRecKeys.filter((x, _) => x[0] == keyId);
                            if (keyPair.length !== 1) {
                                log.warn('BD response does not contain delegation for key pair', keyId);
                                continue;
                            }

                            const pubKey = keyPair[0][1].publicKey;
                            const privKey = keyPair[0][1].privateKey;

                            const recoveryKey = new RecoveryKey(credId, pubKey, privKey, sign)

                            recoveryKeys.push(recoveryKey);
                        }

                        log.debug('Received recovery keys', recoveryKeys);
                        await PSKStorage.storeRecoveryKeys(recoveryKeys);
                    });
            });
    }

    public static async authenticatorMakeCredentialExtensionOutput(): Promise<[string, Uint8Array]> {
        const backupKey = await BackupKey.popBackupKey();
        return [backupKey.credentialId, CBOR.encodeCanonical({bckpDvcAttObj: base64ToByteArray(backupKey.bdAttObj, true)})];
    }

    public static async authenticatorGetCredentialExtensionOutput(): Promise<Uint8Array> {
        return Promise.resolve(undefined); // ToDo Implement
    }
}
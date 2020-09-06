import * as axios from 'axios';
import * as CBOR from 'cbor';

import {PSKStorage} from "./webauth_storage";
import {getLogger} from "./logging";
import {base64ToByteArray, byteArrayToBase64} from "./utils";
import {ECDSA} from "./webauthn_crypto";
import {getAttestationCertificate} from "./webauthn_attestation";
import {Authenticator} from "./webauthn_authenticator";
import {PSK_EXTENSION_IDENTIFIER} from "./constants";

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

    static async findRecoveryKey(credId: string): Promise<RecoveryKey|null> {
        const recoveryKeys =  (await PSKStorage.loadRecoveryKeys()).filter(x => x.credentialId === credId);
        if (recoveryKeys.length == 0) {
            return null
        }

        return recoveryKeys[0];
    }

    static async removeRecoveryKey(credId: string): Promise<void> {
        const recoveryKeys =  (await PSKStorage.loadRecoveryKeys()).filter(x => x.credentialId !== credId);
        return await PSKStorage.storeRecoveryKeys(recoveryKeys);
    }
}

export class PSK {
    public static async bdDeviceUrl(): Promise<string> {
        return await PSKStorage.getBDEndpoint();
    }

    public static async setOptions(alias: string, url: string): Promise<[void, void]> {
        return await Promise.all([PSKStorage.setAlias(alias), PSKStorage.setBDEndpoint(url)]);
    }

    public static async alias(): Promise<string> {
        return await PSKStorage.getAlias();
    }

    public static async setup(): Promise<void> {
        const bdEndpoint = await PSKStorage.getBDEndpoint();
        const authAlias = await this.alias();
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
        const authAlias = prompt('Which authenticator you want to recover?', 'OldAuth');
        const newAuthAlias = await this.alias();
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
                    attCert,
                    newAuthAlias
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

    public static async authenticatorGetCredentialExtensionOutput(oldCredentialId: string, customClientDataHash: Uint8Array, rpId: string): Promise<[string, Uint8Array]> {
        log.debug('authenticatorGetCredentialExtensionOutput called');
        // Find recovery key for given credential id
        const recKey = await RecoveryKey.findRecoveryKey(oldCredentialId);
        if (recKey == null) {
            throw new Error("No recovery key found, but recovery was detected");
        }

        // Create attestation object using the key pair of the recovery key + request PSK extension
        const keyPair = await ECDSA.fromKey(recKey.privKey);
        keyPair.publicKey = recKey.pubKey;
        const authenticatorExtensionInput = new Uint8Array(CBOR.encodeCanonical(null));
        const authenticatorExtensions = new Map([[PSK_EXTENSION_IDENTIFIER, byteArrayToBase64(authenticatorExtensionInput, true)]]);
        const [credentialId, rawAttObj] = await Authenticator.finishAuthenticatorMakeCredential(rpId, customClientDataHash, keyPair, authenticatorExtensions);

        // Finally remove recovery key since PSK output was generated successfully
        await RecoveryKey.removeRecoveryKey(oldCredentialId);

        const recoveryMessage = {attestationObject: rawAttObj, oldCredentialId: oldCredentialId, delegationSignature: recKey.delegationSignature}
        const cborRecMsg = new Uint8Array(CBOR.encodeCanonical(recoveryMessage));
        return [credentialId, cborRecMsg]
    }
}
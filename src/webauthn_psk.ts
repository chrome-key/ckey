import * as axios from 'axios';
import * as CBOR from 'cbor';

import {PinStorage, PSKStorage} from "./webauth_storage";
import {getLogger} from "./logging";
import {base64ToByteArray, byteArrayToBase64} from "./utils";
import {ECDSA} from "./webauthn_crypto";
import {getAttestationCertificate} from "./webauthn_attestation";
import {Authenticator} from "./webauthn_authenticator";
import {BD_TIMEOUT, PSK_EXTENSION_IDENTIFIER} from "./constants";

const log = getLogger('webauthn_psk');

export class BackupKey {
    public bdAttObj: string; // base64 URL with padding

    constructor(attObj: string) {
        this.bdAttObj = attObj;
    }

    static async popBackupKeys(): Promise<BackupKey[]> {
        const bds = await PSKStorage.loadBDs();
        const backupKeys = Array<BackupKey>();

        for (let i = 0; i < bds.length; i++) {
            const bdBackupKeys = await PSKStorage.loadBackupKeys(bds[i]);
            if (bdBackupKeys.length == 0) {
                throw new Error('No backup keys available for ' + bds[i]);
            }
            const backupKey = bdBackupKeys.pop();
            await PSKStorage.storeBackupKeys(bdBackupKeys, bds[i], true);
            backupKeys.push(backupKey);
        }
        if (backupKeys.length == 0) {
            throw new Error('No backup keys available');
        }

        log.debug('Pop backup keys: ', backupKeys)

        return backupKeys;
    }
}

export class RecoveryKey {
    public backupKeyId: string
    public pubKey: CryptoKey
    public privKey: CryptoKey
    public delegationSignature: string
    public bdData: string

    constructor(backupKeyId: string, pubKey: CryptoKey, privKey: CryptoKey, sign: string, bdData: string) {
        this.backupKeyId = backupKeyId;
        this.pubKey = pubKey;
        this.privKey = privKey;
        this.delegationSignature = sign;
        this.bdData = bdData;
    }

    static async findRecoveryKey(backupKeyIds: string[], importPrvKey: boolean = true): Promise<RecoveryKey|null> {
        const recoveryKeys =  await PSKStorage.loadRecoveryKeys(backupKeyIds, importPrvKey);
        if (recoveryKeys.length == 0) {
            return null
        }

        return recoveryKeys[0];
    }

    static async removeRecoveryKey(recKey: RecoveryKey): Promise<void> {
        return await PSKStorage.removeRecoveryKey(recKey);
    }
}

export class PSK {
    public static async bdDeviceUrl(): Promise<string> {
        return await PSKStorage.getBDEndpoint();
    }

    public static async setOptions(alias: string, url: string): Promise<void> {
        return await PSKStorage.setBDEndpoint(url);
    }

    public static async pskSetup(): Promise<void> {
        log.debug('pskSetup triggered');

        const verified = await Authenticator.verifyUser("User verification for PSK setup flow required.");
        if (!verified) {
            throw new Error(`user verification failed for PSK setup flow`);
        }

        const bdEndpoint = await PSKStorage.getBDEndpoint();

        return await axios.default.get(bdEndpoint  + '/setup', {timeout: BD_TIMEOUT})
            .then(async function(response) {
                log.debug(response);
                const syncResponse = response.data;
                const backupKeys = new Array<BackupKey>();
                for (let i = 0; i < syncResponse.backupPublicKeys.length; ++i) {
                    const backupKey = new BackupKey(syncResponse.backupPublicKeys[i].attObj);
                    backupKeys.push(backupKey);
                }
                log.debug('Setup finished. Backup keys', backupKeys);

                await PSKStorage.storeBD(syncResponse.bdUUID);
                await PSKStorage.storeBackupKeys(backupKeys, syncResponse.bdUUID);

                if (syncResponse.hasOwnProperty("recoveryOption")) {
                    await PSK.pskRecoverySetup(syncResponse.authAlias, syncResponse.recoveryOption.originAuthAlias, syncResponse.recoveryOption.keyAmount);
                }
                PinStorage.resetSessionPIN();
            }).catch(e => {
                alert('PSK Initial Setup Failed!');
                log.error(e);
            });
    }

    private static async pskRecoverySetup(delegatedAuthAlias: string, originAuthAlias: string, keyAmount: number): Promise<void> {
        log.debug("pskRecoverySetup triggered");

        const bdEndpoint = await PSKStorage.getBDEndpoint();

        let rawRecKeys = new Map<string, CryptoKeyPair>()
        let replacementKeys = []
        for (let i = 0; i < keyAmount; i++) {
            const keyPair = await window.crypto.subtle.generateKey(
                {name: 'ECDSA', namedCurve: 'P-256'},
                true,
                ['sign'],
            );
            rawRecKeys.set(i.toString(), keyPair);

            // Prepare delegation request
            const pubKey = await ECDSA.fromKey(keyPair.publicKey);
            const cosePubKey = await pubKey.toCOSE(pubKey.publicKey);
            const encodedPubKey = new Uint8Array(CBOR.encodeCanonical(cosePubKey));
            replacementKeys.push({replacementKeyId: i.toString(), pubKey: byteArrayToBase64(encodedPubKey, true)});
        }

        let attCert = byteArrayToBase64(getAttestationCertificate(), true);

        return await axios.default.post(bdEndpoint + '/setup', {
            replacementKeys,
            attCert,
            delegatedAuthAlias,
            originAuthAlias
        }, {timeout: BD_TIMEOUT})
            .then(async function (delResponse) {
                const rawDelegations = delResponse.data.delegations;

                let recoveryKeys = new Array<RecoveryKey>()

                for (let i = 0; i < rawDelegations.length; ++i) {
                    const sign = rawDelegations[i].sign;
                    const backupKeyId = rawDelegations[i].backupKeyId;
                    const replacementKeyId = rawDelegations[i].replacementKeyId;
                    const bdData = rawDelegations[i].bdData;

                    const keyPair = rawRecKeys.get(replacementKeyId)
                    if (!keyPair) {
                        log.warn('BD response does not contain delegation for key pair', replacementKeyId);
                        continue;
                    }

                    const pubKey = keyPair.publicKey;
                    const privKey = keyPair.privateKey;

                    const recoveryKey = new RecoveryKey(backupKeyId, pubKey, privKey, sign, bdData)

                    recoveryKeys.push(recoveryKey);
                }

                log.debug('Recovery Setup finished. Recovery keys:', recoveryKeys);
                await PSKStorage.storeRecoveryKeys(recoveryKeys);
            }).catch(e => {
                alert('PSK Recovery Setup Failed!');
                log.error(e);
            });
    }

    public static async authenticatorMakeCredentialExtensionOutput(): Promise<Uint8Array[]> {
        const backupKeys = await BackupKey.popBackupKeys();
        const raw_backup_keys = Array<Uint8Array>();
        for (let i = 0; i < backupKeys.length; i++) {
            raw_backup_keys.push(base64ToByteArray(backupKeys[i].bdAttObj, true));
        }
        return raw_backup_keys;
    }

    public static async authenticatorGetCredentialExtensionOutput(recoveryKey: RecoveryKey, customClientDataHash: Uint8Array, userHandle: ArrayBuffer, rpId: string): Promise<[string, any]> {
        log.debug('authenticatorGetCredentialExtensionOutput called');

        // Create attestation object using the key pair of the recovery key + request PSK extension
        const keyPair = await ECDSA.fromKey(recoveryKey.privKey);
        keyPair.publicKey = recoveryKey.pubKey;
        const authenticatorExtensionInput = new Uint8Array(CBOR.encodeCanonical(true));
        const authenticatorExtensions = new Map([[PSK_EXTENSION_IDENTIFIER, byteArrayToBase64(authenticatorExtensionInput, true)]]);
        const [credentialId, rawAttObj] = await Authenticator.finishAuthenticatorMakeCredential(rpId, customClientDataHash, true, true, keyPair, authenticatorExtensions, userHandle);

        log.debug('Delegation signature', recoveryKey.delegationSignature);
        log.debug('Attestation object', byteArrayToBase64(rawAttObj, true));
        log.debug('BDData', recoveryKey.bdData);

        // Finally remove recovery key since PSK output was generated successfully
        await RecoveryKey.removeRecoveryKey(recoveryKey);

        const recoveryMessage = {attestationObject: rawAttObj, oldBackupKeyId: base64ToByteArray(recoveryKey.backupKeyId, true), delegationSignature: base64ToByteArray(recoveryKey.delegationSignature, true), bdData: base64ToByteArray(recoveryKey.bdData, true)}
        return [credentialId, recoveryMessage]
    }
}
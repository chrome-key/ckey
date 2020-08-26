import * as axios from 'axios';
import * as CBOR from 'cbor';

import {PSKStorage} from "./webauth_storage";
import {getLogger} from "./logging";
import {base64ToByteArray} from "./utils";

const log = getLogger('webauthn_psk');

export class BackupKey {
    public credentialId: string;
    public bdAttObj: string; // base64 URL with padding

    constructor(credId: string, attObj: string) {
        this.credentialId = credId;
        this.bdAttObj = attObj;
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
                let i;
                const backupKeys = new Array<BackupKey>();
                for (i = 0; i < setupResponse.length; ++i) {
                    const backupKey = new BackupKey(setupResponse[i].credId, setupResponse[i].attObj);
                    backupKeys.push(backupKey);
                }
                log.debug('Loaded backup keys', backupKeys);

                await PSKStorage.storeBackupKeys(backupKeys);
            });
    }

    public static async authenticatorMakeCredentialExtensionOutput(): Promise<[string, Uint8Array]> {
        const backupKey = await this.popBackupKey();
        return [backupKey.credentialId, CBOR.encodeCanonical({bckpDvcAttObj: base64ToByteArray(backupKey.bdAttObj, true)})];
    }

    private static async popBackupKey(): Promise<BackupKey> {
        const backupKeys = await PSKStorage.loadBackupKeys();
        if (backupKeys.length == 0) {
            throw new Error('No backup keys available');
        }
        const backupKey = backupKeys.pop();
        log.debug('Pop backup key', backupKey);
        await PSKStorage.storeBackupKeys(backupKeys, true);

        return backupKey;
    }

    public static async authenticatorGetCredentialExtensionOutput(): Promise<Uint8Array> {
        return Promise.resolve(undefined); // ToDo Implement
    }
}
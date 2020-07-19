import * as CBOR from 'cbor';
import {getCompatibleKey, getCompatibleKeyFromCryptoKey} from './crypto';
import { getLogger } from './logging';
import { fetchKey, keyExists, saveKey } from './storage';
import { base64ToByteArray, byteArrayToBase64, getDomainFromOrigin } from './utils';
import {
    getBackupKey,
    PSK,
    pskSetupExtensionOutput, recover,
} from "./recovery";

const log = getLogger('webauthn');

// Attestation
export const processCredentialCreation = async (
    origin: string,
    publicKeyCreationOptions: PublicKeyCredentialCreationOptions,
    pin: string,
): Promise<PublicKeyCredential> => {
    if (publicKeyCreationOptions.attestation !== 'none') {
        log.warn('We can perform only none attestation');
        return null;
    }

    let supportRecovery = false;
    const reqExt: any = publicKeyCreationOptions.extensions;
    if (reqExt !== undefined) {
        if (reqExt.hasOwnProperty(PSK)) {
            supportRecovery = true;
            log.info('RP supports PSK');
        }
    }

    const rp = publicKeyCreationOptions.rp;
    const rpID = rp.id || getDomainFromOrigin(origin);

    let bckpKey = await getBackupKey();
    log.info('Use backup key', bckpKey);

    const credId = base64ToByteArray(bckpKey.id, true);
    const encCredId = byteArrayToBase64(credId, true);

    if (await keyExists(encCredId)) {
        throw new Error(`credential with id ${encCredId} already exists`);
    }

    let compatibleKey = await getCompatibleKey(publicKeyCreationOptions.pubKeyCredParams);

    let extOutput = null;
    if (supportRecovery) {
        extOutput = await pskSetupExtensionOutput(bckpKey);
    }
    const authenticatorData = await compatibleKey.generateAuthenticatorData(rpID, 0, credId, extOutput);

    // ToDo Add support for credential counter

    const clientData = await compatibleKey.generateClientData(
        publicKeyCreationOptions.challenge as ArrayBuffer,
        { origin, type: 'webauthn.create' },
    );

    const attestationObject = CBOR.encodeCanonical({
        attStmt: new Map(),
        authData: authenticatorData,
        fmt: 'none',
    }).buffer;

    await saveKey(encCredId, compatibleKey.privateKey, pin);

    log.debug('Attestation created');

    return {
        getClientExtensionResults: () => ({}), // ToDo Put PSK extension data
        id: encCredId,
        rawId: credId,
        response: {
            attestationObject,
            clientDataJSON: base64ToByteArray(window.btoa(clientData)),
        },
        type: 'public-key',
    } as PublicKeyCredential;
};

// Assertion
export const processCredentialRequest = async (
    origin: string,
    publicKeyRequestOptions: PublicKeyCredentialRequestOptions,
    pin: string,
): Promise<Credential> => {
    if (!publicKeyRequestOptions.allowCredentials) {
        log.debug('No credentials requested');
        return null;
    }

    const reqExt: any = publicKeyRequestOptions.extensions;
    if (reqExt !== undefined) {
        if (reqExt.hasOwnProperty(PSK)) {
            log.debug('Recovery requested');
            return await recover(origin, publicKeyRequestOptions, pin);
        }
    }

    const requestedCredential = publicKeyRequestOptions.allowCredentials[0]; // ToDo Handle all entries
    const credId: ArrayBuffer = requestedCredential.id as ArrayBuffer;
    const encCredId = byteArrayToBase64(new Uint8Array(credId), true);
    const rpID = publicKeyRequestOptions.rpId || getDomainFromOrigin(origin);

    const key = await fetchKey(encCredId, pin);

    if (!key) {
        throw new Error(`credential with id ${encCredId} not found`);
    }
    const compatibleKey = await getCompatibleKeyFromCryptoKey(key);
    const clientData = await compatibleKey.generateClientData(
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

    // ToDo Update counter
    const authenticatorData = await compatibleKey.generateAuthenticatorData(rpID, 0, new Uint8Array(), null);

    // Prepare input for signature
    const concatData = new Uint8Array(authenticatorData.length + clientDataHash.length);
    concatData.set(authenticatorData);
    concatData.set(clientDataHash, authenticatorData.length);

    const signature = await compatibleKey.sign(concatData);
    log.debug('signature', signature);
    log.debug('clientData', clientData);

    return {
        id: encCredId,
        rawId: credId,
        response: {
            authenticatorData: authenticatorData.buffer,
            clientDataJSON: clientDataJSON,
            signature: (new Uint8Array(signature)).buffer,
            userHandle: new ArrayBuffer(0),
        },
        type: 'public-key',
    } as Credential;
};

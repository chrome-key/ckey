import * as CBOR from 'cbor';
import {createCredentialId, getCompatibleKey, getCompatibleKeyFromCryptoKey} from './crypto';
import { getLogger } from './logging';
import { fetchKey, keyExists, saveKey } from './storage';
import { base64ToByteArray, byteArrayToBase64, getDomainFromOrigin } from './utils';
import {popBackupKey, pskSetupExtensionOutput, syncBackupKeys} from "./recovery";

const log = getLogger('webauthn');

export const generateRegistrationKeyAndAttestation = async (
    origin: string,
    publicKeyCreationOptions: PublicKeyCredentialCreationOptions,
    pin: string,
): Promise<PublicKeyCredential> => {
    if (publicKeyCreationOptions.attestation !== 'none') {
        log.warn('We can perform only none attestation');
        return null;
    }
    log.info(JSON.stringify(publicKeyCreationOptions.extensions));
    // ToDo Trigger PSK flow only if RP signals extension support

    const rp = publicKeyCreationOptions.rp;
    const rpID = rp.id || getDomainFromOrigin(origin);

    // await syncBackupKeys(); // ToDo Add own method to trigger sync

    let bckpKey = await popBackupKey();
    log.info('Used backup key', bckpKey);

    const pskExt = await pskSetupExtensionOutput(bckpKey);

    const credentialId = base64ToByteArray(bckpKey.id, true);
    const encCredId = byteArrayToBase64(credentialId, true);

    // Check if there is already a key for this rp ID
    if (await keyExists(encCredId)) {
        throw new Error(`key with id ${encCredId} already exists`);
    }

    let compatibleKey = await getCompatibleKey(publicKeyCreationOptions.pubKeyCredParams);

    // TODO Increase key counter
    const authenticatorData = await compatibleKey.generateAuthenticatorData(rpID, 0, credentialId, pskExt);
    const clientData = await compatibleKey.generateClientData(
        publicKeyCreationOptions.challenge as ArrayBuffer,
        { origin, type: 'webauthn.create' },
    );

    const attestationObject = CBOR.encodeCanonical({
        attStmt: new Map(),
        authData: authenticatorData,
        fmt: 'none',
    }).buffer;

    // Now that we have built all we need, let's save the key
    await saveKey(encCredId, compatibleKey.privateKey, pin);

    log.debug('send attestation');

    return {
        getClientExtensionResults: () => ({}),
        id: encCredId,
        rawId: credentialId,
        response: {
            attestationObject,
            clientDataJSON: base64ToByteArray(window.btoa(clientData)),
        },
        type: 'public-key',
    } as PublicKeyCredential;
};

// Assertion
export const generateKeyRequestAndAssertion = async (
    origin: string,
    publicKeyRequestOptions: PublicKeyCredentialRequestOptions,
    pin: string,
): Promise<Credential> => {
    if (!publicKeyRequestOptions.allowCredentials) {
        log.debug('No keys requested');
        return null;
    }

    origin = 'http://localhost:9005'; // Given origin does not work!

    // For now we will only worry about the first entry
    const requestedCredential = publicKeyRequestOptions.allowCredentials[0];
    const credentialId: ArrayBuffer = requestedCredential.id as ArrayBuffer;
    const encCredId = byteArrayToBase64(new Uint8Array(credentialId), true);

    const key = await fetchKey(encCredId, pin);

    if (!key) {
        throw new Error(`key with id ${encCredId} not found`);
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

    const rpID = publicKeyRequestOptions.rpId || getDomainFromOrigin(origin);
    const authenticatorData = await compatibleKey.generateAuthenticatorData(rpID, 0, new Uint8Array(), null);

    const concatData = new Uint8Array(authenticatorData.length + clientDataHash.length);
    concatData.set(authenticatorData);
    concatData.set(clientDataHash, authenticatorData.length);

    const signature = await compatibleKey.sign(concatData);
    log.info('signature', signature);
    return {
        id: encCredId,
        rawId: credentialId,
        response: {
            authenticatorData: authenticatorData.buffer,
            clientDataJSON: clientDataJSON,
            signature: (new Uint8Array(signature)).buffer,
            userHandle: new ArrayBuffer(0), // This should be nullable
        },
        type: 'public-key',
    } as Credential;
};

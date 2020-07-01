import * as CBOR from 'cbor';
import {createCredentialId, getCompatibleKey, getCompatibleKeyFromCryptoKey} from './crypto';
import { getLogger } from './logging';
import { fetchKey, keyExists, saveKey } from './storage';
import { base64ToByteArray, byteArrayToBase64, getDomainFromOrigin } from './utils';

const log = getLogger('webauthn');

export const generateRegistrationKeyAndAttestation = async (
    origin: string,
    publicKeyCreationOptions: PublicKeyCredentialCreationOptions,
    pin: string,
): Promise<PublicKeyCredential> => {
    if (publicKeyCreationOptions.attestation === 'direct') {
        log.warn('We are being requested to create a key with "direct" attestation');
        log.warn(`We can only perform self-attestation, therefore we will not be provisioning any keys`);
        return null;
    }
    const rp = publicKeyCreationOptions.rp;
    const rpID = rp.id || getDomainFromOrigin(origin);
    const user = publicKeyCreationOptions.user;
    const userID = byteArrayToBase64(new Uint8Array(user.id as ArrayBuffer));

    const credentialId = createCredentialId();
    const encCredId = byteArrayToBase64(credentialId, true);

    // First check if there is already a key for this rp ID
    if (await keyExists(encCredId)) {
        throw new Error(`key with id ${encCredId} already exists`);
    }

    const compatibleKey = await getCompatibleKey(publicKeyCreationOptions.pubKeyCredParams);

    // TODO Increase key counter
    // ToDo Use correct credential Id in authenticator & authenticator data
    const authenticatorData = await compatibleKey.generateAuthenticatorData(rpID, 0, credentialId);
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
    const endCredId = byteArrayToBase64(new Uint8Array(credentialId), true);

    const key = await fetchKey(endCredId, pin);

    if (!key) {
        throw new Error(`key with id ${endCredId} not found`);
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
    const authenticatorData = await compatibleKey.generateAuthenticatorData(rpID, 0, new Uint8Array());

    const concatData = new Uint8Array(authenticatorData.length + clientDataHash.length);
    concatData.set(authenticatorData);
    concatData.set(clientDataHash, authenticatorData.length);

    const signature = await compatibleKey.sign(concatData);
    log.info('signature', signature);
    return {
        id: endCredId,
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

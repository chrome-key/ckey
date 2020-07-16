import * as CBOR from 'cbor';
import { getCompatibleKey, getCompatibleKeyFromCryptoKey } from './crypto';
import { getLogger } from './logging';
import { fetchKey, keyExists, saveKey } from './storage';
import { base64ToByteArray, byteArrayToBase64, getDomainFromOrigin } from './utils';

const log = getLogger('webauthn');

export const generateAttestationResponse = async (
    origin: string,
    publicKeyCreationOptions: PublicKeyCredentialCreationOptions,
    pin: string,
): Promise<PublicKeyCredential> => {
    if (publicKeyCreationOptions.attestation !== 'none') {
        log.warn(`We are being requested to create a credential with ${publicKeyCreationOptions.attestation} attestation`);
        log.warn(`We can only perform none attestation, therefore we will not be provisioning any credentials`);
        return null;
    }
    const rp = publicKeyCreationOptions.rp;
    const rpID = rp.id || getDomainFromOrigin(origin);
    const credId = createCredentialId();
    const encCredId = byteArrayToBase64(credId, true);

    // First check if there is already a key for this rp ID
    if (await keyExists(encCredId)) {
        throw new Error(`credential with id ${encCredId} already exists`);
    }
    log.debug('key ID', encCredId);
    const compatibleKey = await getCompatibleKey(publicKeyCreationOptions.pubKeyCredParams);

    // TODO Increase key counter
    const authenticatorData = await compatibleKey.generateAuthenticatorData(rpID, 0, credId);
    const clientData = await compatibleKey.generateClientData(
        publicKeyCreationOptions.challenge as ArrayBuffer,
        { origin, type: 'webauthn.create' },
    );

    const attestationObject = CBOR.encodeCanonical({
        attStmt: new Map(),
        authData: authenticatorData,
        fmt: 'none',
    }).buffer;

    // Now that we have built all we need, let's save the private key
    await saveKey(encCredId, compatibleKey.privateKey, pin);

    return {
        getClientExtensionResults: () => ({}),
        id: encCredId,
        rawId: credId,
        response: {
            attestationObject,
            clientDataJSON: base64ToByteArray(window.btoa(clientData)),
        },
        type: 'public-key',
    } as PublicKeyCredential;
};

export const generateAssertionResponse = async (
    origin: string,
    publicKeyRequestOptions: PublicKeyCredentialRequestOptions,
    pin: string,
): Promise<Credential> => {
    if (!publicKeyRequestOptions.allowCredentials) {
        log.debug('No credentials requested');
        return null;
    }

    // For now we will only worry about the first entry
    const requestedCredential = publicKeyRequestOptions.allowCredentials[0];
    const credId: ArrayBuffer = requestedCredential.id as ArrayBuffer;
    const endCredId = byteArrayToBase64(new Uint8Array(credId), true);
    const rpID = publicKeyRequestOptions.rpId || getDomainFromOrigin(origin);

    log.debug('credential ID', endCredId);

    const key = await fetchKey(endCredId, pin);

    if (!key) {
        throw new Error(`credentials with id ${endCredId} not found`);
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
    const authenticatorData = await compatibleKey.generateAuthenticatorData(rpID, 0, new Uint8Array());
    const clientDataJSON = base64ToByteArray(window.btoa(clientData));
    const clientDataHash = new Uint8Array(await window.crypto.subtle.digest('SHA-256', clientDataJSON));

    const concatData = new Uint8Array(authenticatorData.length + clientDataHash.length);
    concatData.set(authenticatorData);
    concatData.set(clientDataHash, authenticatorData.length);


    const signature = await compatibleKey.sign(concatData);

    return {
        id: endCredId,
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

function createCredentialId(): Uint8Array{
    let enc =  new TextEncoder();
    let dt = new Date().getTime();
    const uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = (dt + Math.random()*16)%16 | 0;
        dt = Math.floor(dt/16);
        return (c=='x' ? r :(r&0x3|0x8)).toString(16);
    });
    return base64ToByteArray(byteArrayToBase64(enc.encode(uuid), true), true);
}

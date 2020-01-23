import * as CBOR from 'cbor';
import { getCompatibleKey, getCompatibleKeyFromCryptoKey } from './crypto';
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
    const keyID = window.btoa(`${userID}@${rpID}`);

    // First check if there is already a key for this rp ID
    if (await keyExists(keyID)) {
        throw new Error(`key with id ${keyID} already exists`);
    }
    log.debug('key ID', keyID);
    const compatibleKey = await getCompatibleKey(publicKeyCreationOptions.pubKeyCredParams);

    // TODO Increase key counter
    const authenticatorData = await compatibleKey.generateAuthenticatorData(rpID, 0);
    const clientData = await compatibleKey.generateClientData(
        publicKeyCreationOptions.challenge as ArrayBuffer,
        { origin, type: 'webauthn.create' },
    );
    const signature = await compatibleKey.sign(clientData);

    const attestationObject = CBOR.encodeCanonical({
        attStmt: {
            alg: compatibleKey.algorithm,
            sig: signature,
        },
        authData: authenticatorData,
        fmt: 'packed',
    }).buffer;

    // Now that we have built all we need, let's save the key
    await saveKey(keyID, compatibleKey.privateKey, pin);

    return {
        getClientExtensionResults: () => ({}),
        id: keyID,
        rawId: base64ToByteArray(keyID),
        response: {
            attestationObject,
            clientDataJSON: base64ToByteArray(window.btoa(clientData)),
        },
        type: 'public-key',
    } as PublicKeyCredential;
};

export const generateKeyRequestAndAttestation = async (
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
    const keyIDArray: ArrayBuffer = requestedCredential.id as ArrayBuffer;
    const keyID = byteArrayToBase64(new Uint8Array(keyIDArray));
    const key = await fetchKey(keyID, pin);

    if (!key) {
        throw new Error(`key with id ${keyID} not found`);
    }
    const compatibleKey = await getCompatibleKeyFromCryptoKey(key);
    const clientData = await compatibleKey.generateClientData(
        publicKeyRequestOptions.challenge as ArrayBuffer,
        {
            origin,
            tokenBinding: {
                status: 'not-supported',
            },
            type: 'webauthn.create',
        },
    );
    const signature = await compatibleKey.sign(clientData);
    const rpID = publicKeyRequestOptions.rpId || getDomainFromOrigin(origin);
    const authenticatorData = await compatibleKey.generateAuthenticatorData(rpID, 0);
    return {
        id: keyID,
        rawId: keyIDArray,
        response: {
            authenticatorData: authenticatorData.buffer,
            clientDataJSON: base64ToByteArray(window.btoa(clientData)),
            signature,
            userHandle: new ArrayBuffer(0), // This should be nullable
        },
        type: 'public-key',
    } as Credential;
};

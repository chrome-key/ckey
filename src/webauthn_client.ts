import {base64ToByteArray, byteArrayToBase64, getDomainFromOrigin} from "./utils";
import {Authenticator} from "./webauthn_authenticator";
import {getLogger} from "./logging";

type FunctionType = string;
const Create: FunctionType = "webauthn.create";
const Get: FunctionType = "webauthn.get";

const log = getLogger('webauthn_authenticator');

export async function createPublicKeyCredential(origin: string, options: CredentialCreationOptions, sameOriginWithAncestors: boolean): Promise<PublicKeyCredential> {
    log.debug('Called createPublicKeyCredential');

    // Step 2
    if (!sameOriginWithAncestors) {
        throw new Error(`sameOriginWithAncestors has to be true`);
    }

    // Step 7
    const rpID = options.publicKey.rp.id || getDomainFromOrigin(origin);

    // Step 11
    // ToDo clientExtensions + authenticatorExtensions

    // Step 13 + 14
    const clientDataJSON = generateClientDataJSON(Create, options.publicKey.challenge as ArrayBuffer, origin);

    // Step 15
    const clientDataHashDigest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(clientDataJSON)));
    const clientDataHash = new Uint8Array(clientDataHashDigest);

    // Step 20: Simplified, just for 1 authenticator
    const userVerification = options.publicKey.authenticatorSelection.requireUserVerification === "required";
    const userPresence = !userVerification;

    const attObjWrapper = await Authenticator.authenticatorMakeCredential(clientDataHash,
        options.publicKey.rp,
        options.publicKey.user,
        options.publicKey.authenticatorSelection.requireResidentKey,
        userPresence,
        userVerification,
        options.publicKey.pubKeyCredParams,
        options.publicKey.excludeCredentials);

    log.debug('Received attestation object');

    return {
        getClientExtensionResults: () => ({}),
        id: attObjWrapper.credentialId,
        rawId: base64ToByteArray(attObjWrapper.credentialId, true),
        response: {
            attestationObject: attObjWrapper.rawAttObj.buffer,
            clientDataJSON: base64ToByteArray(window.btoa(JSON.stringify(clientDataJSON))),
        },
        type: 'public-key',
    } as PublicKeyCredential;
}

export async function getPublicKeyCredential(origin: string, options: CredentialRequestOptions, sameOriginWithAncestors: boolean) {
    // Step 2
    if (!sameOriginWithAncestors) {
        throw new Error(`sameOriginWithAncestors has to be true`);
    }

    // Step 7
    const rpID = options.publicKey.rpId || getDomainFromOrigin(origin);

    // Step 8 + 9
    // ToDo Each authenticator extension is an client extension!

    // Step 10 + 11
    const clientDataJSON = generateClientDataJSON(Get, options.publicKey.challenge as ArrayBuffer, origin);

    // Step 12
    const clientDataHashDigest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(clientDataJSON)));
    const clientDataHash = new Uint8Array(clientDataHashDigest);

    // Step 18: Simplified, just for 1 authenticator
    const userVerification = options.publicKey.userVerification === "required";
    const userPresence = !userVerification;
    const assertionCreationData = await Authenticator.authenticatorGetAssertion(options.publicKey.rpId,
        clientDataHash,
        userPresence,
        userVerification,
        options.publicKey.allowCredentials);

    log.debug('Received assertion response');

    return {
        getClientExtensionResults: () => ({}),
        id: assertionCreationData.credentialId,
        rawId: base64ToByteArray(assertionCreationData.credentialId, true),
        response: {
            authenticatorData: assertionCreationData.authenticatorData.buffer,
            clientDataJSON: base64ToByteArray(window.btoa(JSON.stringify(clientDataJSON))),
            signature: assertionCreationData.signature.buffer,
            userHandle: assertionCreationData.userHandle,
        },
        type: 'public-key',
    } as PublicKeyCredential;
}

function generateClientDataJSON(type: FunctionType, challenge: ArrayBuffer, origin: string, tokenBinding?: string): any {
    return {
        type: type,
        challenge: byteArrayToBase64(Buffer.from(challenge), true),
        origin: origin,
    }
}
import * as CBOR from 'cbor';
import {base64ToByteArray, byteArrayToBase64, getDomainFromOrigin} from "./utils";
import {Authenticator} from "./webauthn_authenticator";
import {getLogger} from "./logging";
import {PSK_EXTENSION_IDENTIFIER} from "./constants";

type FunctionType = string;
const Create: FunctionType = "webauthn.create";
const Get: FunctionType = "webauthn.get";

const log = getLogger('webauthn_client');

export async function createPublicKeyCredential(origin: string, options: CredentialCreationOptions, sameOriginWithAncestors: boolean, userConsentCallback: Promise<boolean>): Promise<PublicKeyCredential> {
    log.debug('Called createPublicKeyCredential');

    // Step 2
    if (!sameOriginWithAncestors) {
        throw new Error(`sameOriginWithAncestors has to be true`);
    }

    // Step 7
    options.publicKey.rp.id = options.publicKey.rp.id || getDomainFromOrigin(origin);

    // Step 11
    let clientExtensions = undefined;
    let authenticatorExtensions = undefined;
    if (options.publicKey.extensions) {
        const reqExt: any = options.publicKey.extensions;
        if (reqExt.hasOwnProperty(PSK_EXTENSION_IDENTIFIER)) {
            log.debug('PSK extension requested');
            if (reqExt[PSK_EXTENSION_IDENTIFIER] == true) {
                log.debug('PSK extension has valid client input');
                const authenticatorExtensionInput = new Uint8Array(CBOR.encodeCanonical(null));
                authenticatorExtensions = new Map([[PSK_EXTENSION_IDENTIFIER, byteArrayToBase64(authenticatorExtensionInput, true)]]);
                clientExtensions = {[PSK_EXTENSION_IDENTIFIER]: true};
            }
        }
    }

    // Step 13 + 14
    const clientDataJSON = generateClientDataJSON(Create, options.publicKey.challenge as ArrayBuffer, origin);

    // Step 15
    const clientDataHashDigest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(clientDataJSON)));
    const clientDataHash = new Uint8Array(clientDataHashDigest);

    // Step 20: Simplified, just for 1 authenticator
    let userVerification = false;
    let residentKey = false;
    if (options.publicKey.authenticatorSelection) {
        userVerification = options.publicKey.authenticatorSelection.requireUserVerification === "required";
        residentKey = options.publicKey.authenticatorSelection.requireResidentKey;
    }
    const userPresence = !userVerification;

    const attObjWrapper = await Authenticator.authenticatorMakeCredential(userConsentCallback,
        clientDataHash,
        options.publicKey.rp,
        options.publicKey.user,
        residentKey,
        userPresence,
        userVerification,
        options.publicKey.pubKeyCredParams,
        options.publicKey.excludeCredentials,
        authenticatorExtensions);

    log.debug('Received attestation object');

    return {
        getClientExtensionResults: () => (clientExtensions),
        id: attObjWrapper.credentialId,
        rawId: base64ToByteArray(attObjWrapper.credentialId, true),
        response: {
            attestationObject: attObjWrapper.rawAttObj.buffer,
            clientDataJSON: base64ToByteArray(window.btoa(JSON.stringify(clientDataJSON))),
        },
        type: 'public-key',
    } as PublicKeyCredential;
}

export async function getPublicKeyCredential(origin: string, options: CredentialRequestOptions, sameOriginWithAncestors: boolean, userConsentCallback: Promise<boolean>) {
    // Step 2
    if (!sameOriginWithAncestors) {
        throw new Error(`sameOriginWithAncestors has to be true`);
    }

    // Step 7
    const rpID = options.publicKey.rpId || getDomainFromOrigin(origin);

    // Step 8 + 9
    let clientExtensions = undefined;
    let authenticatorExtensions = undefined;
    if (options.publicKey.extensions) {
        const reqExt: any = options.publicKey.extensions;
        if (reqExt.hasOwnProperty(PSK_EXTENSION_IDENTIFIER)) {
            log.debug('PSK extension requested');
            if (reqExt[PSK_EXTENSION_IDENTIFIER] == true) {
                log.debug('PSK extension has valid client input');
                const customClientDataJSON = generateClientDataJSON(Create, options.publicKey.challenge as ArrayBuffer, origin);
                const customClientDataHashDigest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(customClientDataJSON)));
                const customClientDataHash = new Uint8Array(customClientDataHashDigest);
                const authenticatorExtensionInput = new Uint8Array(CBOR.encodeCanonical({hash: customClientDataHash}));
                authenticatorExtensions = new Map([[PSK_EXTENSION_IDENTIFIER, byteArrayToBase64(authenticatorExtensionInput, true)]]);
                clientExtensions = {[PSK_EXTENSION_IDENTIFIER]: {clientDataJSON: customClientDataJSON}}; // ToDo Add to response
            }
        }
    }

    // Step 10 + 11
    const clientDataJSON = generateClientDataJSON(Get, options.publicKey.challenge as ArrayBuffer, origin);

    // Step 12
    const clientDataHashDigest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(clientDataJSON)));
    const clientDataHash = new Uint8Array(clientDataHashDigest);

    // Step 18: Simplified, just for 1 authenticator
    const userVerification = options.publicKey.userVerification === "required";
    const userPresence = !userVerification;
    const assertionCreationData = await Authenticator.authenticatorGetAssertion(userConsentCallback,
        rpID,
        clientDataHash,
        userPresence,
        userVerification,
        options.publicKey.allowCredentials,
        authenticatorExtensions);

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
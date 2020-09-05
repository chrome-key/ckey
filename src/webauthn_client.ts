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

    // Step 1
    if (!options.publicKey) {
        throw new Error('options missing');
    }

    // Step 2
    if (!sameOriginWithAncestors) {
        throw new Error(`sameOriginWithAncestors has to be true`);
    }

    // Skip timeout

    // Step 7
    options.publicKey.rp.id = options.publicKey.rp.id || getDomainFromOrigin(origin);

    // Step 8-10
    const credTypesAndPubKeyAlgs = options.publicKey.pubKeyCredParams;

    // Step 11 + 12
    // Only PSK extension is processed
    let clientExtensions = undefined;
    let authenticatorExtensions = undefined;
    if (options.publicKey.extensions) {
        const reqExt: any = options.publicKey.extensions;
        if (reqExt.hasOwnProperty(PSK_EXTENSION_IDENTIFIER)) {
            log.info('PSK extension requested');
            if (reqExt[PSK_EXTENSION_IDENTIFIER] == true) {
                log.debug('PSK extension has valid client input');
                const authenticatorExtensionInput = new Uint8Array(CBOR.encodeCanonical(null));
                authenticatorExtensions = new Map([[PSK_EXTENSION_IDENTIFIER, byteArrayToBase64(authenticatorExtensionInput, true)]]);
                clientExtensions = {[PSK_EXTENSION_IDENTIFIER]: true};
            } else {
                log.warn('PSK client extension processing failed. Wrong input.');
            }
        }
    }

    // Step 13 + 14
    const clientDataJSON = generateClientDataJSON(Create, options.publicKey.challenge as ArrayBuffer, origin);

    // Step 15
    const clientDataHashDigest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(clientDataJSON)));
    const clientDataHash = new Uint8Array(clientDataHashDigest);

    // Handle only 1 authenticator
    // Step 20, simplified
    if (options.publicKey.authenticatorSelection) {
        if (options.publicKey.authenticatorSelection.authenticatorAttachment && (options.publicKey.authenticatorSelection.authenticatorAttachment !== 'platform')) {
            throw new Error(`${options.publicKey.authenticatorSelection.authenticatorAttachment} authenticator requested, but only platform authenticators available`);
        }


        // Resident key check can be omitted, because cKey supports resident keys

        if (options.publicKey.authenticatorSelection.userVerification && (options.publicKey.authenticatorSelection.userVerification === 'required')) {
            throw new Error(`cKey does not support user verification`);
        }
    }


    let userVerification = false;
    let residentKey = false;
    if (options.publicKey.authenticatorSelection) {
        userVerification = options.publicKey.authenticatorSelection.requireUserVerification === "required";
        residentKey = options.publicKey.authenticatorSelection.requireResidentKey;
    }
    const userPresence = !userVerification;

    const excludeCredentialDescriptorList = options.publicKey.excludeCredentials // No filtering

    const [credentialId, rawAttObj] = await Authenticator.authenticatorMakeCredential(userConsentCallback,
        clientDataHash,
        options.publicKey.rp,
        options.publicKey.user,
        residentKey,
        userPresence,
        userVerification,
        credTypesAndPubKeyAlgs,
        excludeCredentialDescriptorList,
        authenticatorExtensions);

    log.debug('Received attestation object');

    if (options.publicKey.attestation === 'none') { // Currently only direct and indirect attestation is supported
        throw new Error('Client does not support none attestation');
    }

    return {
        getClientExtensionResults: () => (clientExtensions), // ToDo Fix client extension output
        id: credentialId,
        rawId: base64ToByteArray(credentialId, true),
        response: {
            attestationObject: rawAttObj.buffer,
            clientDataJSON: base64ToByteArray(window.btoa(JSON.stringify(clientDataJSON))),
        },
        type: 'public-key',
    } as PublicKeyCredential;
}

export async function getPublicKeyCredential(origin: string, options: CredentialRequestOptions, sameOriginWithAncestors: boolean, userConsentCallback: Promise<boolean>) {
    // Step 1
    if (!options.publicKey) {
        throw new Error('options missing');
    }

    // Step 2
    if (!sameOriginWithAncestors) {
        throw new Error(`sameOriginWithAncestors has to be true`);
    }

    // No timeout

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
                // clientExtensions = {[PSK_EXTENSION_IDENTIFIER]: {clientDataJSON: customClientDataJSON}}; // ToDo  Add to response
            } else {
                log.warn('PSK client extension processing failed. Wrong input.');
            }
        }
    }

    // Step 10 + 11
    const clientDataJSON = generateClientDataJSON(Get, options.publicKey.challenge as ArrayBuffer, origin);

    // Step 12
    const clientDataHashDigest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(clientDataJSON)));
    const clientDataHash = new Uint8Array(clientDataHashDigest);

    // Handle only 1 authenticator
    // Step 18
    if (options.publicKey.userVerification && (options.publicKey.userVerification === 'required')) {
        throw new Error(`cKey does not support user verification`);
    }

    const userVerification = options.publicKey.userVerification === "required";
    const userPresence = !userVerification;

    const allowCredentialDescriptorList = options.publicKey.allowCredentials; // No filtering

    const assertionCreationData = await Authenticator.authenticatorGetAssertion(userConsentCallback,
        rpID,
        clientDataHash,
        userPresence,
        userVerification,
        allowCredentialDescriptorList,
        authenticatorExtensions);

    log.debug('Received assertion response');

    return {
        getClientExtensionResults: () => (clientExtensions), // ToDo Add client extension output
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
import {base64ToByteArray, byteArrayToBase64} from "./utils";
import {Authenticator} from "./webauthn_authenticator";
import {getLogger} from "./logging";

type FunctionType = string;
const Create: FunctionType = "webauthn.create"

const log = getLogger('webauthn_authenticator');

export async function createPublicKeyCredential(origin: string, options: CredentialCreationOptions, sameOriginWithAncestors: boolean): Promise<PublicKeyCredential> {
    log.debug('Called createPublicKeyCredential');
    if (options.publicKey.attestation) {
        if (options.publicKey.attestation !== "direct") {
            throw new Error(`Only direct attestation supported`);
        }
    }

    const clientDataJSON = generateClientDataJSON(Create, options.publicKey.challenge as ArrayBuffer, origin);

    const clientDataHashDigest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(clientDataJSON)));
    const clientDataHash = new Uint8Array(clientDataHashDigest);

    const requireUserVerification = options.publicKey.authenticatorSelection.requireUserVerification === "required"

    const attObjWrapper = await Authenticator.authenticatorMakeCredential(clientDataHash,
        options.publicKey.rp,
        options.publicKey.user,
        options.publicKey.authenticatorSelection.requireResidentKey,
        !requireUserVerification,
        requireUserVerification,
        options.publicKey.pubKeyCredParams,
        options.publicKey.excludeCredentials) // ToDo Add extensions map

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

function generateClientDataJSON(type: FunctionType, challenge: ArrayBuffer, origin: string, tokenBinding?: string): any {
    return {
        type: type,
        challenge: byteArrayToBase64(Buffer.from(challenge), true),
        origin: origin,
    }
}
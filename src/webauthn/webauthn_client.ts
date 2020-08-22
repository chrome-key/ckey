import {byteArrayToBase64} from "../utils";

type FunctionType = string;
const Create: FunctionType = "webauthn.create"

async function createPublicKeyCredential(origin: string, options: CredentialCreationOptions, sameOriginWithAncestors: boolean): Promise<PublicKeyCredential> {
    const clientDataJSON = generateClientDataJSON(Create, options.publicKey.challenge as ArrayBuffer, origin);

    const clientDataHashDigest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(clientDataJSON)));
    const clientDataHash = new Uint8Array(clientDataHashDigest);
}

function generateClientDataJSON(type: FunctionType, challenge: ArrayBuffer, origin: string, tokenBinding?: string): any {
    return {
        type: type,
        challenge: byteArrayToBase64(Buffer.from(challenge), true),
        origin: origin,
    }
}
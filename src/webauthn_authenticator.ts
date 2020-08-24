import {ECDSA, ICOSECompatibleKey} from "./webauthn_crypto";
import {CredentialsMap, PublicKeyCredentialSource} from "./webauth_storage";
import {base64ToByteArray, byteArrayToBase64, counterToBytes} from "./utils";
import * as CBOR from 'cbor';
import {createAttestationSignature, getAttestationCertificate} from "./webauthn_attestation";
import {getLogger} from "./logging";
import {ES256_COSE} from "./constants";

const log = getLogger('webauthn_authenticator');

export class AttestationObjectWrapper {
    public credentialId: string
    public rawAttObj: Uint8Array

    constructor(credId: string, raw: Uint8Array) {
        this.credentialId = credId;
        this.rawAttObj = raw;
    }
}

export class AssertionResponse {
    public authenticatorData: Uint8Array
    public signature: Uint8Array
    public userHandle: Uint8Array
    public credentialId: string

    constructor(credId: string, authData: Uint8Array, sign: Uint8Array, userHandle: Uint8Array) {
        this.authenticatorData = authData;
        this.signature = sign;
        this.userHandle = userHandle;
        this.credentialId = credId;
    }
}

export class Authenticator {
    private static AAGUID: Uint8Array = new Uint8Array([
        1214244733, 1205845608, 840015201, 3897052717,
        4072880437, 4027233456, 675224361, 2305433287,
        74291263, 3461796691, 701523034, 3178201666,
        3992003567, 1410532, 4234129691, 1438515639,
    ]);

    private static getSignatureCounter(): number {
        return 0;
    }

    public static async authenticatorGetAssertion(userConsentCallback: Promise<boolean>,
                                                  rpId: string,
                                                  hash: Uint8Array,
                                                  requireUserPresence: boolean,
                                                  requireUserVerification: boolean,
                                                  allowCredentialDescriptorList?: PublicKeyCredentialDescriptor[],
                                                  extensions?: any
                                                  ): Promise<AssertionResponse> {

        log.debug('Called authenticatorGetAssertion');

        // Step 2-7
        let credentialOptions: PublicKeyCredentialSource[] = [];
        if (allowCredentialDescriptorList) {
            for (let i = 0; i < allowCredentialDescriptorList.length; i++) {
                const rawCredId = allowCredentialDescriptorList[i].id as ArrayBuffer;
                const credId = byteArrayToBase64(new Uint8Array(rawCredId), true);
                const cred = await CredentialsMap.lookup(rpId, credId);
                if (cred != null) {
                    credentialOptions.push(cred);
                }
            }
        } else {
            credentialOptions = credentialOptions.concat(await CredentialsMap.load(rpId));
        }
        if (credentialOptions.length == 0) {
            throw new Error(`Container does not manage any related credentials`);
        }
        // Note: The authenticator won't let the user select a public key credential source
        const credSource = credentialOptions[0];


        const userConsent = await userConsentCallback;
        if (!userConsent) {
            throw new Error(`no user consent`);
        }

        // Step 8
        // ToDo Include Extension Processing
        const processedExtensions = undefined;

        // Step 9: The current version does not increment counter

        // Step 10
        const authenticatorData = await this.generateAuthenticatorData(rpId,
            this.getSignatureCounter(), undefined, processedExtensions);

        // Step 11
        const concatData = new Uint8Array(authenticatorData.length + hash.length);
        concatData.set(authenticatorData);
        concatData.set(hash, authenticatorData.length);
        const prvKey = await ECDSA.fromKey(credSource.privateKey);
        const signature = await prvKey.sign(concatData);

        // Step 13
        return new AssertionResponse(credSource.id, authenticatorData, signature, credSource.userHandle);
    }

    public static async authenticatorMakeCredential(userConsentCallback: Promise<boolean>,
                                             hash: Uint8Array,
                                             rpEntity: PublicKeyCredentialRpEntity,
                                             userEntity: PublicKeyCredentialUserEntity,
                                             requireResidentKey: boolean,
                                             requireUserPresence: boolean,
                                             requireUserVerification: boolean,
                                             credTypesAndPubKeyAlgs:  PublicKeyCredentialParameters[],
                                             excludeCredentialDescriptorList?: PublicKeyCredentialDescriptor[],
                                             extensions?: any): Promise<AttestationObjectWrapper> {
        log.debug('Called authenticatorMakeCredential');

        // Step 2
        let algCheck = false;
        for (let i = 0; i < credTypesAndPubKeyAlgs.length; i++) {
            if (credTypesAndPubKeyAlgs[i].alg == ES256_COSE) {
                algCheck = true;
                break;
            }
        }
        if (!algCheck) {
            throw new Error(`authenticator does not support requested alg`);
        }

        // Step 3
        if (excludeCredentialDescriptorList) {
            const credMapEntries = await CredentialsMap.load(rpEntity.id);
            for (let i = 0; i < excludeCredentialDescriptorList.length; i++) {
                const rawCredId = excludeCredentialDescriptorList[i].id as ArrayBuffer;
                const credId = byteArrayToBase64(new Uint8Array(rawCredId), true);
                if (credMapEntries.findIndex(x =>
                    (x.id == credId) && (x.type === excludeCredentialDescriptorList[i].type)) >= 0) {
                    throw new Error(`authenticator manages credential of excludeCredentialDescriptorList`);
                }
            }
        }

        // Step 5
        if (requireUserVerification) {
            throw new Error(`authenticator does not support user verification`);
        }

        // Step 6
        const userConsent = await userConsentCallback;
        if (!userConsent) {
            throw new Error(`no user consent`);
        }

        // Step 7
        const credentialId = this.createCredentialId();
        const keyPair = await ECDSA.createECDSAKeyPair();
        const credentialSource = new PublicKeyCredentialSource(credentialId, keyPair.privateKey, rpEntity.id); // No user Handle
        await CredentialsMap.put(rpEntity.id, credentialSource);

        // Step 9
        // ToDo Include Extension Processing
        const extensionData = undefined;

        // Step 10
        const sigCnt = this.getSignatureCounter();

        // Step 11
        const rawCredentialId = base64ToByteArray(credentialId, true);
        const attestedCredentialData = await this.generateAttestedCredentialData(rawCredentialId, keyPair);

        // Step 12
        const authenticatorData = await this.generateAuthenticatorData(rpEntity.id, sigCnt, attestedCredentialData, extensionData);

        // Step 13
        const attObj = await this.generateAttestationObject(hash, authenticatorData);

        // Return value is not 1:1 WebAuthn conform
        log.debug('Created credential', credentialId)
        return (new AttestationObjectWrapper(credentialId, attObj));

    }

    private static async generateAttestedCredentialData(credentialId: Uint8Array, keyPair: ICOSECompatibleKey): Promise<Uint8Array> {
        const aaguid = this.AAGUID.slice(0, 16);
        const credIdLen = new Uint8Array(2);
        credIdLen[0] = (credentialId.length >> 8) & 0xff;
        credIdLen[1] = credentialId.length & 0xff;
        const coseKey = await keyPair.toCOSE(keyPair.publicKey);
        const encodedKey = new Uint8Array(CBOR.encodeCanonical(coseKey));

        const attestedCredentialDataLength = aaguid.length + credIdLen.length + credentialId.length + encodedKey.length;
        const attestedCredentialData = new Uint8Array(attestedCredentialDataLength);

        let offset = 0;
        attestedCredentialData.set(aaguid, offset);
        offset += aaguid.length;

        attestedCredentialData.set(credIdLen, offset);
        offset += credIdLen.length;

        attestedCredentialData.set(credentialId, offset);
        offset += credentialId.length;

        attestedCredentialData.set(encodedKey, offset);

        return attestedCredentialData;
    }

    private static async generateAuthenticatorData(rpID: string, counter: number, attestedCredentialData?: Uint8Array,
                                             extensionData?: Uint8Array): Promise<Uint8Array> {
        const rpIdDigest = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpID));
        const rpIdHash = new Uint8Array(rpIdDigest);
        let authenticatorDataLength = rpIdHash.length + 1 + 4;
        if (attestedCredentialData) {
            authenticatorDataLength += attestedCredentialData.byteLength;
        }
        if (extensionData) {
            authenticatorDataLength += extensionData.byteLength;
        }

        const authenticatorData = new Uint8Array(authenticatorDataLength);
        let offset = 0;

        // 32 bytes for the RP ID hash
        authenticatorData.set(rpIdHash, offset);
        offset += rpIdHash.length;

        // 1 byte for flags
        authenticatorData[rpIdHash.length] = 1; // UP
        if (attestedCredentialData) {
            authenticatorData[rpIdHash.length] |= (1 << 6); // AT
        }
        if (extensionData) {
            authenticatorData[rpIdHash.length] |= (1 << 7); // ED
        }
        offset++;

        // 4 bytes for the counter. big-endian uint32
        // https://www.w3.org/TR/webauthn/#signature-counter
        authenticatorData.set(counterToBytes(counter), offset);
        offset += counterToBytes(counter).length;

        if (attestedCredentialData) {
            authenticatorData.set(attestedCredentialData, offset);
            offset += attestedCredentialData.byteLength;
        }
        if (extensionData) {
            authenticatorData.set(extensionData, offset);
        }
        return authenticatorData;
    }

    private static async generateAttestationObject(hash: Uint8Array, authenticatorData: Uint8Array): Promise<Uint8Array> {
        const attCert = getAttestationCertificate();
        const attSignature = await createAttestationSignature(hash, authenticatorData);
        const attObjJSON = {
            authData: authenticatorData,
            fmt: 'packed',
            attStmt: {
                alg: ES256_COSE,
                sig: attSignature,
                x5c: [attCert]
            }
        }
        return CBOR.encodeCanonical(attObjJSON);

    }

    private static createCredentialId(): string{
        let enc =  new TextEncoder();
        let dt = new Date().getTime();
        const uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = (dt + Math.random()*16)%16 | 0;
            dt = Math.floor(dt/16);
            return (c=='x' ? r :(r&0x3|0x8)).toString(16);
        });
        return byteArrayToBase64(enc.encode(uuid), true);
    }
}
import {ECDSA, ICOSECompatibleKey} from "./webauthn_crypto";
import {CredentialsMap, PinStorage, PublicKeyCredentialSource} from "./webauth_storage";
import {base64ToByteArray, byteArrayToBase64, counterToBytes} from "./utils";
import * as CBOR from 'cbor';
import {createAttestationSignature, getAttestationCertificate} from "./webauthn_attestation";
import {getLogger} from "./logging";
import {ES256_COSE, PSK_EXTENSION_IDENTIFIER} from "./constants";
import {PSK, RecoveryKey} from "./webauthn_psk";

const log = getLogger('webauthn_authenticator');

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

    public static async authenticatorGetAssertion(userConsentCallback: () => Promise<boolean>,
                                                  rpId: string,
                                                  hash: Uint8Array,
                                                  requireUserPresence: boolean,
                                                  requireUserVerification: boolean,
                                                  allowCredentialDescriptorList?: PublicKeyCredentialDescriptor[],
                                                  extensions?: Map<string, string>
                                                  ): Promise<AssertionResponse> {

        log.debug('Called authenticatorGetAssertion');

        // Step 2-7 + recovery lookup
        let isRecovery: RecoveryKey = null;
        let credentialOptions: PublicKeyCredentialSource[] = [];
        if (allowCredentialDescriptorList) {
            // Simplified credential lookup
            for (let i = 0; i < allowCredentialDescriptorList.length; i++) {
                const rawCredId = allowCredentialDescriptorList[i].id as ArrayBuffer;
                const credId = byteArrayToBase64(new Uint8Array(rawCredId), true);
                const cred = await CredentialsMap.lookup(rpId, credId);
                if (cred != null) {
                    credentialOptions.push(cred);
                }
            }
        } else {
            // If no credentials were supplied, load all credentials associated to the RPID
            credentialOptions = credentialOptions.concat(await CredentialsMap.load(rpId));
        }
        if (credentialOptions.length == 0) {
            // Check if there is any recovery key that matches the provided credential descriptors
            log.debug('No directly managed credentials found');
            for (let i = 0; i < allowCredentialDescriptorList.length; i++) {
                const rawCredId = allowCredentialDescriptorList[i].id as ArrayBuffer;
                const credId = byteArrayToBase64(new Uint8Array(rawCredId), true);
                isRecovery = await RecoveryKey.findRecoveryKey(credId);
                if (isRecovery != null) {
                    log.info('Recovery detected for', credId);
                    break;
                }
            }
            if (isRecovery == null) {
                // No recovery and no associated credential found
                throw new Error(`Container does not manage any related credentials`);
            }
        }
        // Note: The authenticator won't let the user select a public key credential source
        let credSource;
        if (isRecovery == null) { // No recovery
            credSource = credentialOptions[0];
        }

        const up = await userConsentCallback();
        if (!up) {
            throw new Error(`no user consent`);
        }

        // USer verification is always performed, because PIN is needed to decrypt keys
        let uv = await this.verifyUser("User verification is required.");
        if (!uv) {
            throw new Error(`user verification failed`);
        }

        // Step 8
        let processedExtensions = undefined;
        if (extensions) {
            if (extensions.has(PSK_EXTENSION_IDENTIFIER)) {
                log.debug('Get: PSK requested');
                if (isRecovery == null) {
                    throw new Error('PSK extension requested, but no matching recovery key available');
                }
                const rawPskInput = base64ToByteArray(extensions.get(PSK_EXTENSION_IDENTIFIER), true);
                const pskInput = await CBOR.decode(new Buffer(rawPskInput));
                const [newCredId, pskOutput] = await PSK.authenticatorGetCredentialExtensionOutput(isRecovery, pskInput, rpId);
                processedExtensions = new Map([[PSK_EXTENSION_IDENTIFIER, pskOutput]]);
                credSource = await CredentialsMap.lookup(rpId, newCredId);
                if (credSource == null) {
                    // This should never happen
                    throw new Error('Get: New credential source missing');
                }
                log.debug('Get: Processed PSK');
            } else if (isRecovery != null) {
                throw new Error('Recovery detected, but no PSK requested.')
            }
        } else if (isRecovery != null) {
            throw new Error('Recovery detected, but no PSK requested.')
        }

        if (processedExtensions) {
            processedExtensions =  new Uint8Array(CBOR.encodeCanonical(processedExtensions));
        }

        // Step 9: The current version does not increment the counter

        // Step 10
        const authenticatorData = await this.generateAuthenticatorData(rpId,
            this.getSignatureCounter(), undefined, processedExtensions, up, uv);

        // Step 11
        const concatData = new Uint8Array(authenticatorData.length + hash.length);
        concatData.set(authenticatorData);
        concatData.set(hash, authenticatorData.length);
        const prvKey = await ECDSA.fromKey(credSource.privateKey);
        const signature = await prvKey.sign(concatData);

        // Step 13
        return new AssertionResponse(credSource.id, authenticatorData, signature, credSource.userHandle);
    }

    public static async authenticatorMakeCredential(userConsentCallback: () => Promise<boolean>,
                                             hash: Uint8Array,
                                             rpEntity: PublicKeyCredentialRpEntity,
                                             userEntity: PublicKeyCredentialUserEntity,
                                             requireResidentKey: boolean,
                                             requireUserPresence: boolean,
                                             requireUserVerification: boolean,
                                             credTypesAndPubKeyAlgs:  PublicKeyCredentialParameters[],
                                             excludeCredentialDescriptorList?: PublicKeyCredentialDescriptor[],
                                             extensions?: Map<string, string>): Promise<[string, Uint8Array]> {
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
        if (excludeCredentialDescriptorList) { // Simplified look up
            const credMapEntries = await CredentialsMap.load(rpEntity.id);
            for (let i = 0; i < excludeCredentialDescriptorList.length; i++) {
                const rawCredId = excludeCredentialDescriptorList[i].id as ArrayBuffer;
                const credId = byteArrayToBase64(new Uint8Array(rawCredId), true);
                if (credMapEntries.findIndex(x =>
                    (x.id == credId) && (x.type === excludeCredentialDescriptorList[i].type)) >= 0) {
                    await userConsentCallback;
                    throw new Error(`authenticator manages credential of excludeCredentialDescriptorList`);
                }
            }
        }

        // Step 4 Not needed, because cKey supports resident keys

        // Step 5 + 6
        const up = await userConsentCallback(); // User presence always checked
        if (!up) {
            throw new Error(`no user consent`);
        }

        // User verification is always performed, because PIN is needed to decrypt keys
        let uv = await this.verifyUser("The relying party requires user verification.");
        if (!uv) {
            throw new Error(`user verification failed`);
        }

        return await this.finishAuthenticatorMakeCredential(rpEntity.id, hash, uv, up,undefined, extensions, userEntity.id);
    }

    public static async finishAuthenticatorMakeCredential(rpId: string, hash: Uint8Array, uv: boolean, up:boolean, keyPair?: ICOSECompatibleKey, extensions?: Map<string, string>, userHandle?: BufferSource): Promise<[string, Uint8Array]> {
        // Step 7
        if (!(keyPair)) {
            log.debug('No key pair provided, create new one.');
            keyPair = await ECDSA.createECDSAKeyPair();
        }
        let credentialId = this.createCredentialId();
        let credentialSource = new PublicKeyCredentialSource(credentialId, keyPair.privateKey, rpId, (<Uint8Array>userHandle));
        await CredentialsMap.put(rpId, credentialSource);

        // Step 9
        let processedExtensions = undefined;
        if (extensions) {
            log.debug(extensions);
            if (extensions.has(PSK_EXTENSION_IDENTIFIER)) {
                log.debug('Make: PSK requested');
                const rawPskInput = base64ToByteArray(extensions.get(PSK_EXTENSION_IDENTIFIER), true);
                const pskInput = await CBOR.decode(new Buffer(rawPskInput));
                if (pskInput !== true) {
                    log.warn('Make: PSK extension received unexpected input. Skip extension processing.', extensions[PSK_EXTENSION_IDENTIFIER]);
                } else {
                    const pskOutPut = await PSK.authenticatorMakeCredentialExtensionOutput();
                    processedExtensions = new Map([[PSK_EXTENSION_IDENTIFIER, pskOutPut]]);
                    log.debug('Make: Processed PSK');
                }

            }
        }
        if (processedExtensions) {
            processedExtensions =  new Uint8Array(CBOR.encodeCanonical(processedExtensions));
            log.debug('CBOR extension', Buffer.from(processedExtensions).toString('hex'));
        }


        // Step 10
        const sigCnt = this.getSignatureCounter();

        // Step 11
        const rawCredentialId = base64ToByteArray(credentialId, true);
        const attestedCredentialData = await this.generateAttestedCredentialData(rawCredentialId, keyPair);

        // Step 12
        const authenticatorData = await this.generateAuthenticatorData(rpId, sigCnt, attestedCredentialData, processedExtensions, up, uv);

        // Step 13
        const attObj = await this.generateAttestationObject(hash, authenticatorData);

        // Return value is not 1:1 WebAuthn conform
        log.debug('Created credential', credentialId)
        return [credentialId, attObj];
    }

    private static async generateAttestedCredentialData(credentialId: Uint8Array, publicKey: ICOSECompatibleKey): Promise<Uint8Array> {
        const aaguid = this.AAGUID.slice(0, 16);
        const credIdLen = new Uint8Array(2);
        credIdLen[0] = (credentialId.length >> 8) & 0xff;
        credIdLen[1] = credentialId.length & 0xff;
        const coseKey = await publicKey.toCOSE(publicKey.publicKey);
        const encodedKey = new Uint8Array(CBOR.encodeCanonical(coseKey));
        log.debug('New pub key', byteArrayToBase64(encodedKey, true));

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
                                             extensionData?: Uint8Array, up?: boolean, uv?: boolean): Promise<Uint8Array> {
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
        if (up) {
            authenticatorData[rpIdHash.length] = 1; // UP
        }
        if (uv) {
           authenticatorData[rpIdHash.length] |= (1 << 2); // AT
        }
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

    public static  async verifyUser(message: string): Promise<boolean> {
        const bcrypt = require('bcryptjs');

        const userPin = prompt(`${message}\nPlease enter your PIN.`, "");
        const pinHash = await PinStorage.getPinHash();
        const match = bcrypt.compareSync(userPin, pinHash);

        PinStorage.setSessionPIN(userPin);
        return match
    }
}
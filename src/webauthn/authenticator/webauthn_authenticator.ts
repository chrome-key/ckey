import {ECDSA, ES256_COSE} from "./webauthn_crypto";
import {CredentialsMap, PublicKeyCredentialSource} from "./auth_storage";
import {byteArrayToBase64} from "../../utils";

class Authenticator {
    private static AAGUID: Uint8Array = new Uint8Array([
        1214244733, 1205845608, 840015201, 3897052717,
        4072880437, 4027233456, 675224361, 2305433287,
        74291263, 3461796691, 701523034, 3178201666,
        3992003567, 1410532, 4234129691, 1438515639,
    ]);

    private static getSignatureCounter(): number {
        return 0;
    }

    public static async authenticatorMakeCredential(hash: Uint8Array,
                                             rpEntity: PublicKeyCredentialRpEntity,
                                             userEntity: PublicKeyCredentialUserEntity,
                                             requireResidentKey: boolean,
                                             requireUserPresence: boolean,
                                             requireUserVerification: boolean,
                                             credTypesAndPubKeyAlgs:  PublicKeyCredentialParameters[],
                                             excludeCredentialDescriptorList?: PublicKeyCredentialDescriptor[],
                                             extensions?: any): Promise<Buffer> {
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
                if (credMapEntries.findIndex(x => x.id == credId) < 0) {
                    throw new Error(`authenticator manages credential of excludeCredentialDescriptorList`);
                }
            }
        }

        // Step 6
        // ToDo User Consent

        // Step 5
        if (requireUserVerification) {
            throw new Error(`authenticator does not support user verification`);
        }

        // Step 7
        const credentialId = ""// ToDo Create id
        const keyPair = await ECDSA.createECDSAKeyPair();
        const credSrc = new PublicKeyCredentialSource(credentialId, keyPair.privateKey, rpEntity.id) // No User Handle
        await CredentialsMap.put(rpEntity.id, credSrc);

        // Step 9
        // ToDo Include Extension Processing

        // Step 10
        const sigCnt = this.getSignatureCounter();
    }

    private static async generateAttestedCredentialData(): Promise<Uint8Array> {

        // 16 bytes for the Authenticator Attestation GUID
        authenticatorData.set(aaguid, offset);
        offset += aaguid.length;

        // 2 bytes for the authenticator key ID length. 16-bit unsigned big-endian integer.
        authenticatorData.set(credIdLen, offset);
        offset += credIdLen.length;

        // Variable length authenticator key ID
        authenticatorData.set(credentialId, offset);
        offset += credentialId.length;

        // Variable length public key
        authenticatorData.set(encodedKey, offset);
        offset += encodedKey.length;
    }
}
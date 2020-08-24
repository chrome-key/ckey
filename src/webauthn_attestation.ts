import {ECDSA, ICOSECompatibleKey, importFromJWK} from "./webauthn_crypto";

const PrivateKeyPEM = '-----BEGIN EC PRIVATE KEY-----\n' +
    'MHcCAQEEIOOF5RiIjzKZCCtFJLMxAFB4O8WvnhAsWuF9YacETrWgoAoGCCqGSM49\n' +
    'AwEHoUQDQgAEaixHolNWEXlB7JdX+2WgUeM3BfbvLPsVaNKe+Efu4ea3iMBvNelS\n' +
    '5jOgQ2DYpKv6FHtoUhT6rBpzYmc/pgd6XA==\n' +
    '-----END EC PRIVATE KEY-----';

const AttestationCertificatePEM = '-----BEGIN CERTIFICATE-----\n' +
    'MIIDLzCCAtWgAwIBAgIJAOe4D4tkNjKBMAoGCCqGSM49BAMCMIGwMQswCQYDVQQG\n' +
    'EwJERTEPMA0GA1UECAwGU2F4b255MRAwDgYDVQQHDAdEcmVzZGVuMRowGAYDVQQK\n' +
    'DBFBdXRoIEV4YW1wbGUsIExMQzEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRl\n' +
    'c3RhdGlvbjEdMBsGA1UEAwwUQXV0aCBFeGFtcGxlIENvbXBhbnkxHzAdBgkqhkiG\n' +
    '9w0BCQEWEHRlc3RAZXhhbXBsZS5jb20wHhcNMjAwODIzMDkzODM1WhcNMjEwODIz\n' +
    'MDkzODM1WjCBsDELMAkGA1UEBhMCREUxDzANBgNVBAgMBlNheG9ueTEQMA4GA1UE\n' +
    'BwwHRHJlc2RlbjEaMBgGA1UECgwRQXV0aCBFeGFtcGxlLCBMTEMxIjAgBgNVBAsM\n' +
    'GUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xHTAbBgNVBAMMFEF1dGggRXhhbXBs\n' +
    'ZSBDb21wYW55MR8wHQYJKoZIhvcNAQkBFhB0ZXN0QGV4YW1wbGUuY29tMFkwEwYH\n' +
    'KoZIzj0CAQYIKoZIzj0DAQcDQgAEaixHolNWEXlB7JdX+2WgUeM3BfbvLPsVaNKe\n' +
    '+Efu4ea3iMBvNelS5jOgQ2DYpKv6FHtoUhT6rBpzYmc/pgd6XKOB1TCB0jAdBgNV\n' +
    'HQ4EFgQU6EhpfP6IdPer5CCYCIsbDOexo2YwHwYDVR0jBBgwFoAU6EhpfP6IdPer\n' +
    '5CCYCIsbDOexo2YwCQYDVR0TBAIwADALBgNVHQ8EBAMCBaAwSgYDVR0RBEMwQYIL\n' +
    'ZXhhbXBsZS5jb22CD3d3dy5leGFtcGxlLmNvbYIQbWFpbC5leGFtcGxlLmNvbYIP\n' +
    'ZnRwLmV4YW1wbGUuY29tMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRl\n' +
    'ZCBDZXJ0aWZpY2F0ZTAKBggqhkjOPQQDAgNIADBFAiEA4Rwn4jcj50HYQ5N6UJaT\n' +
    'UxuwhZgl5yLEJOzvY3a2V/gCIFwJNEMUE0PeRrhUoEWmj1zg2kV8EEzHO1bio6q0\n' +
    'o9rQ\n' +
    '-----END CERTIFICATE-----';

export async function createAttestationSignature(hash: Uint8Array, authData: Uint8Array): Promise<Uint8Array> {
    const attPrvKey = await getAttestationPrivateKey();
    const concatData = new Uint8Array(authData.length + hash.length);
    concatData.set(authData);
    concatData.set(hash, authData.length);
    return await attPrvKey.sign(concatData);
}

async function getAttestationPrivateKey(): Promise<ICOSECompatibleKey> {
    const ECKey = require('ec-key');
    const prvKey = new ECKey(Buffer.from(PrivateKeyPEM), 'pem');
    const jwk = JSON.stringify(prvKey, null, 2);
    const key = await importFromJWK(JSON.parse(jwk), ['sign']);
    return ECDSA.fromKey(key);
}

export function getAttestationCertificate(): Uint8Array {
    const pem = require('pem-file')
    return pem.decode(Buffer.from(AttestationCertificatePEM));
}


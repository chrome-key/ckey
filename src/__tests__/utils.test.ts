import {
    base64ToByteArray,
    byteArrayToBase64,
    getDomainFromOrigin,
    getOriginFromUrl,
} from '../utils';

describe('getDomainFromOrigin', () => {
    it('removes HTTP schemes', () => {
        ['http', 'https'].forEach((scheme) => {
            const expectedDomain = 'google.com';
            expect(getDomainFromOrigin(`${scheme}://${expectedDomain}`))
                .toMatch(expectedDomain);
        });
    });

    it('does not change unknown schemes', () => {
        ['sip', 'ftp'].forEach((scheme) => {
            const expectedDomain = `${scheme}://google.com`;
            expect(getDomainFromOrigin(expectedDomain)).toMatch(expectedDomain);
        });
    });
});

describe('getOriginFromUrl', () => {
    it('removes paths', () => {
        ['http', 'https'].forEach((scheme) => {
            ['', '/', '/somepath', 'somepath?param=123'].forEach((path) => {
                const expectedDomain = 'google.com';
                expect(getOriginFromUrl(`${scheme}://${expectedDomain}${path}`))
                    .toMatch(`${scheme}://${expectedDomain}`);
            });
        });
    });

    it('does not process unknown schemes', () => {
        ['sip', 'ftp'].forEach((scheme) => {
            ['', '/', '/somepath', 'somepath?param=123'].forEach((path) => {
                const expectedDomain = 'google.com';
                expect(getOriginFromUrl(`${scheme}://${expectedDomain}${path}`))
                    .toBeNull();
            });
        });
    });
});

describe('byteArrayToBase64', () => {
    it('encodes properly', () => {
        const inputs = Uint8Array.of(508, 1, 3, 250);
        expect(byteArrayToBase64(inputs)).toEqual('/AED+g==');
    });

    it('URL encodes properly', () => {
        const inputs = Uint8Array.of(508, 1, 3, 250);
        expect(byteArrayToBase64(inputs, true)).toEqual('_AED-g');
    });
});

describe('base64ToByteArray', () => {
    it('decodes properly', () => {
        const outputs = Uint8Array.of(508, 1, 3, 250);
        expect(base64ToByteArray('/AED+g==')).toEqual(outputs);
    });

    it('URL decodes properly', () => {
        const outputs = Uint8Array.of(508, 1, 3, 250);
        expect(base64ToByteArray('_AED-g', true)).toEqual(outputs);
    });

    it('fails on invalid input', (done) => {
        try {
            base64ToByteArray('/AED+==');
        } catch {
            done();
        }
    });
});

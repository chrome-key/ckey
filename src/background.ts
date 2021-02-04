import {disabledIcons, enabledIcons} from './constants';

import {getLogger} from './logging';

import {getOriginFromUrl, webauthnParse, webauthnStringify} from './utils';

import {createPublicKeyCredential, getPublicKeyCredential} from "./webauthn_client";
import {PSK} from "./webauthn_psk";
import {PinStorage} from "./webauth_storage";

const log = getLogger('background');

chrome.runtime.onInstalled.addListener(() => {
    log.info('Extension installed');
});

const userConsentCallbacks: { [tabId: number]: (consent: boolean) => void } = {};

const requestUserConsent = async (tabId: number, origin: string): Promise<boolean> => {
    const tabKey = `tab-${tabId}`;
    chrome.storage.local.set({ [tabKey]: { origin } }, () => {
        if (chrome.runtime.lastError) {
            throw new Error(`failed to store value: ${chrome.runtime.lastError}`);
        }
    });
    log.debug('setting popup for tab', tabId);

    const cb: Promise<boolean> = new Promise((res, _) => {
        userConsentCallbacks[tabId] = res;
    });

    chrome.pageAction.setIcon({ tabId, path: enabledIcons });
    chrome.pageAction.setPopup({ tabId, popup: 'popup.html' });
    chrome.pageAction.show(tabId);
    const userConsent = await cb;
    chrome.storage.local.remove(tabKey);
    chrome.pageAction.setPopup({ tabId, popup: '' });
    chrome.pageAction.hide(tabId);
    chrome.pageAction.setIcon({ tabId, path: disabledIcons });
    return userConsent;
};

const createCredential = async (msg, sender: chrome.runtime.MessageSender) => {
    if (!sender.tab || !sender.tab.id) {
        log.debug('received createCredential event without a tab ID');
        return;
    }
    const opts = webauthnParse(msg.options);
    const origin = getOriginFromUrl(sender.url);
    const userConsentCB = function() { return requestUserConsent(sender.tab.id, origin); }

    try {
        const credential = await createPublicKeyCredential(
            origin,
            opts,
            true,
            userConsentCB
        );
        return {
            credential: webauthnStringify(credential),
            clientExtensionResults: credential.getClientExtensionResults(),
            requestID: msg.requestID,
            type: 'create_credential_response',
        };
    } catch (e) {
        log.error('failed to register credential', { errorType: `${(typeof e)}` }, e);
    }
};

const getCredential = async (msg, sender: chrome.runtime.MessageSender) => {
    if (!sender.tab || !sender.tab.id) {
        log.debug('received getCredential event without a tab ID');
        return;
    }
    const opts = webauthnParse(msg.options);
    const origin = getOriginFromUrl(sender.url);
    const userConsentCB = function() { return requestUserConsent(sender.tab.id, origin); }

    try {
        const credential = await getPublicKeyCredential(origin, opts, true, userConsentCB);
        return {
            credential: webauthnStringify(credential),
            requestID: msg.requestID,
            clientExtensionResults: credential.getClientExtensionResults(),
            type: 'get_credential_response',
        };
    } catch (e) {
        log.error('failed to create credential assertion', { errorType: `${(typeof e)}` }, e);
    }
};

const pskSync = async () => {
    await PSK.pskSetup();
};

const pskOptions = async (alias, url) => {
    await PSK.setOptions(alias, url);
};

const authSetup = async () => {
    let pin = await PinStorage.getPinHash().catch(_ => null);
    if (pin != null) {
        throw new Error("PIN already set");
    }
    pin = prompt("Please enter a PIN for the authenticator", "");
    if (pin == null) {
        throw new Error("Invalid PIN");
    }
    return await PinStorage.setPin(pin);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    switch (msg.type) {
        case 'create_credential':
            createCredential(msg, sender).then(sendResponse);
            break;
        case 'get_credential':
            getCredential(msg, sender).then(sendResponse);
            break;
        case 'psk_setup':
            pskSync().then(() => {}, e => log.error('PSK setup flow failed', { errorType: `${(typeof e)}` }, e));
            break;
        case 'psk_options':
            pskOptions(msg.alias, msg.url).then(() => alert('PSK options set successfully.'),   e => log.error('failed to set psk options', { errorType: `${(typeof e)}` }, e));
            break;
        case 'auth_pin_set':
            authSetup().then(() => alert('Authenticator PIN setup was successful.'), e => alert(e));
            break;
        case 'user_consent':
            const cb = userConsentCallbacks[msg.tabId];
            if (!cb) {
                log.warn(`Received user consent for tab ${msg.tabId} but no callback registered`);
            } else {
                cb(msg.userConsent);
                delete (userConsentCallbacks[msg.tabId]);
            }
            break;

        default:
            sendResponse(null);
    }
    return true;
});

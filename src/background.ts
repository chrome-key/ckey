import {disabledIcons, enabledIcons} from './constants';
import {getLogger} from './logging';
import {getOriginFromUrl, webauthnParse, webauthnStringify} from './utils';
import {generateKeyRequestAndAssertion, generateRegistrationKeyAndAttestation} from './webauthn';
import {syncBackupKeys, syncDelegation} from "./recovery";

const log = getLogger('background');

chrome.runtime.onInstalled.addListener(() => {
    log.info('Extension installed');
});

const pinProtectedCallbacks: { [tabId: number]: (pin: number) => void } = {};

const requestPin = async (tabId: number, origin: string, newPin: boolean = true): Promise<number> => {
    const tabKey = `tab-${tabId}`;
    chrome.storage.local.set({ [tabKey]: { origin, newPin } }, () => {
        if (chrome.runtime.lastError) {
            throw new Error(`failed to store value: ${chrome.runtime.lastError}`);
        }
    });
    log.debug('setting popup for tab', tabId);
    const cb: Promise<number> = new Promise((res, _) => {
        pinProtectedCallbacks[tabId] = res;
    });
    chrome.pageAction.setIcon({ tabId, path: enabledIcons });
    chrome.pageAction.setPopup({ tabId, popup: 'popup.html' });
    chrome.pageAction.show(tabId);
    const pin = await cb;
    chrome.storage.local.remove(tabKey);
    chrome.pageAction.setPopup({ tabId, popup: '' });
    chrome.pageAction.hide(tabId);
    chrome.pageAction.setIcon({ tabId, path: disabledIcons });
    return pin;
};

const syncBackup = async (backupContent) => {
    console.log('Sync Backup called');

    await syncBackupKeys(backupContent);
};

const syncDel = async (delegationContent) => {
    console.log('Sync Delegation called');

    await syncDelegation(delegationContent);
};

const create = async (msg, sender: chrome.runtime.MessageSender) => {
    if (!sender.tab || !sender.tab.id) {
        log.debug('received create event without a tab ID');
        return;
    }

    const origin = getOriginFromUrl(sender.url);
    const pin = await requestPin(sender.tab.id, origin);

    try {
        const opts = webauthnParse(msg.options);
        const credential = await generateRegistrationKeyAndAttestation(
            origin,
            opts.publicKey,
            `${pin}`,
        );
        return {
            credential: webauthnStringify(credential),
            requestID: msg.requestID,
            type: 'create_response',
        };
    } catch (e) {
        if (e instanceof DOMException) {
            const { code, message, name } = e;
            log.error('failed to import key due to DOMException', { code, message, name }, e);
        } else {
            log.error('failed to import key', { errorType: `${(typeof e)}` }, e);
        }
    }
};

const sign = async (msg, sender: chrome.runtime.MessageSender) => {
    const opts = webauthnParse(msg.options);
    const origin = getOriginFromUrl(sender.url);
    const pin = await requestPin(sender.tab.id, origin);

    try {
        const credential = await generateKeyRequestAndAssertion(origin, opts.publicKey, `${pin}`);
        return {
            credential: webauthnStringify(credential),
            requestID: msg.requestID,
            type: 'sign_response',
        };
    } catch (e) {
        if (e instanceof DOMException) {
            const { code, message, name } = e;
            log.error('failed to sign due DOMException', { code, message, name }, e);
        } else {
            log.error('failed to sign', { errorType: `${(typeof e)}` }, e);
        }
    }
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    switch (msg.type) {
        case 'create':
            create(msg, sender).then(sendResponse);
            break;
        case 'sign':
            sign(msg, sender).then(sendResponse);
            break;
        case 'pin':
            const cb = pinProtectedCallbacks[msg.tabId];
            if (!cb) {
                log.warn(`Received pin for tab ${msg.tabId} but no callback registered`);
            } else {
                cb(msg.pin);
                delete (pinProtectedCallbacks[msg.tabId]);
            }
            break;
        case 'syncBackup':
            syncBackup(msg.backup).then(() => alert("Backup file processed"));
            break;
        case 'syncDelegation':
            syncDel(msg.delegation).then(() => alert("Delegation file processed"));
            break;
        default:
            sendResponse(null);
    }

    return true;
});

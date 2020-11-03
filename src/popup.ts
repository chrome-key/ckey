import $ from 'jquery';
import { getLogger } from './logging';

const log = getLogger('popup');

$(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs: chrome.tabs.Tab[]) => {
        const currentTab = tabs.find((t) => !!t.id);
        if (!currentTab) {
            return;
        }

        $('#userConsent').on('click', function(evt: Event) {
            evt.preventDefault();
            evt.stopPropagation();

            chrome.runtime.sendMessage({
                userConsent: true,
                tabId: currentTab.id,
                type: 'user_consent',
            });
            window.close();
            return false;
        });

        const tabKey = `tab-${currentTab.id}`;
        chrome.storage.local.get([tabKey], (result) => {
            $('#domain').text(result[tabKey].origin);
        });
    });
});

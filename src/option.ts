import $ from 'jquery';

$(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs: chrome.tabs.Tab[]) => {
        const currentTab = tabs.find((t) => !!t.id);
        if (!currentTab) {
            return;
        }

        $('#Setup').on('click', function(evt: Event) {
            evt.preventDefault();
            chrome.runtime.sendMessage({
                type: 'setup',
            });
        });

        $('#Recovery').on('click', function(evt: Event) {
            evt.preventDefault();
            chrome.runtime.sendMessage({
                type: 'recovery',
            });
        });
    });
});

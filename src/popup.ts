import $ from 'jquery';
import { getLogger } from './logging';

const log = getLogger('popup');


$(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs: chrome.tabs.Tab[]) => {
        const currentTab = tabs.find((t) => !!t.id);
        if (!currentTab) {
            return;
        }

        $('#delegationFile').on('change', function(evt: Event) {
            const files =  (<HTMLInputElement>evt.target).files; // FileList object

            // use the 1st file from the list
            const f = files[0];

            const reader = new FileReader();

            // Closure to capture the file information.
            reader.onload = (function(theFile) {
                return function(e) {
                    chrome.runtime.sendMessage({
                        delegation: e.target.result,
                        type: 'syncDelegation',
                    });
                };
            })(f);

            // Read in the image file as a data URL.
            reader.readAsText(f);
        });
        $('#backupFile').on('change', function(evt: Event) {
            evt.preventDefault();
            const files =  (<HTMLInputElement>evt.target).files; // FileList object

            // use the 1st file from the list
            const f = files[0];

            const reader = new FileReader();

            // Closure to capture the file information.
            reader.onload = (function(theFile) {
                return function(e) {
                    chrome.runtime.sendMessage({
                        backup: e.target.result,
                        type: 'syncBackup',
                    });
                };
            })(f);

            // Read in the image file as a data URL.
            reader.readAsText(f);
        });


        const tabKey = `tab-${currentTab.id}`;
        chrome.storage.local.get([tabKey], (result) => {
            log.debug('got storage results', result);
            const pinPromise: Promise<number> = new Promise((res, _) => {
                $('#domain').text(result[tabKey].origin);
                $('input').first().focus();
                prepareInputs(res);
            });
            pinPromise.then((pin) => {
                log.debug('continue with pin', pin);
                chrome.runtime.sendMessage({
                    pin,
                    tabId: currentTab.id,
                    type: 'pin',
                });
                window.close();
            });
        });
    });

    // Inspired by https://codepen.io/nirarazi/pen/ZGovQo
    const prepareInputs = (res: (n: number) => void) => {
        const body = $('body');

        const goToNextInput = (e: JQueryEventObject) => {
            const key = e.which;
            const t = $(e.target);
            const sib = t.next('input');
            if (key !== 9 && (key < 48 || key > 57)) {
                e.preventDefault();
                return false;
            }
            if (key === 9) {
                return true;
            }
            if (!sib || !sib.length) {
                let pin = 0;
                $('input', $('body')).each((n, v) => {
                    pin = pin * 10;
                    pin += +$(v).val();
                });
                res(pin);
                return false;
            }
            sib.select().focus();
        };

        const onKeyDown = (e: JQueryEventObject) => {
            const key = e.which;
            if (key === 9 || (key >= 48 && key <= 57)) {
                return true;
            }
            e.preventDefault();
            return false;
        };

        const onFocus = (e: JQueryEventObject) => $(e.target).select();

        body.on('keyup', 'input', goToNextInput);
        body.on('keydown', 'input', onKeyDown);
        body.on('click', 'input', onFocus);
    };
});

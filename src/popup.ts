import $ from 'jquery';
import { getLogger } from './logging';

const log = getLogger('popup');


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

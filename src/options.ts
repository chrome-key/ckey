import $ from 'jquery';
import {getBackupDeviceBaseUrl} from "./recovery";

$(() => {
    $('#Setup').on('click', function(evt: Event) {
        evt.preventDefault();
        chrome.runtime.sendMessage({
            type: 'setup',
        });
    });

    $.when(getBackupDeviceBaseUrl()).then((url) => $('#BackupDeviceUrl').val(url));

    $('#Recovery').on('click', function(evt: Event) {
        evt.preventDefault();
        chrome.runtime.sendMessage({
            type: 'recovery',
        });
    });

    $('#SaveBackupDeviceUrl').on('click', function(evt: Event) {
        evt.preventDefault();
        chrome.runtime.sendMessage({
            type: 'saveOptions',
            url: $('#BackupDeviceUrl').val(),
        });
    });
});

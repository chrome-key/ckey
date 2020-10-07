import $ from 'jquery';
import {PSK} from "./webauthn_psk";

$(() => {
    $.when(PSK.bdDeviceUrl()).then((url) => $('#BackupDeviceUrl').val(url));

    $('#Sync').on('click', function(evt: Event) {
        evt.preventDefault();
        chrome.runtime.sendMessage({
            type: 'psk_sync',
        });
    });

    $('#SaveOptions').on('click', function(evt: Event) {
        evt.preventDefault();
        chrome.runtime.sendMessage({
            type: 'psk_options',
            url: $('#BackupDeviceUrl').val(),
        });
    });

    $('#Setup').on('click', function(evt: Event) {
        evt.preventDefault();
        chrome.runtime.sendMessage({
            type: 'auth_setup',
        });
    });
});

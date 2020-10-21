import $ from 'jquery';
import {PSK} from "./webauthn_psk";

$(() => {
    $.when(PSK.bdDeviceUrl()).then((url) => $('#BackupDeviceUrl').val(url));

    $('#Sync').on('click', function(evt: Event) {
        evt.preventDefault();
        chrome.runtime.sendMessage({
            type: 'psk_setup',
        });
    });

    $('#SaveOptions').on('click', function(evt: Event) {
        evt.preventDefault();
        chrome.runtime.sendMessage({
            type: 'psk_options',
            url: $('#BackupDeviceUrl').val(),
        });
    });

    $('#Pin').on('click', function(evt: Event) {
        evt.preventDefault();
        chrome.runtime.sendMessage({
            type: 'auth_pin_set',
        });
    });
});

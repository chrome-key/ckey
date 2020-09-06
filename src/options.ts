import $ from 'jquery';
import {PSK} from "./webauthn_psk";

$(() => {
    $('#Setup').on('click', function(evt: Event) {
        evt.preventDefault();
        chrome.runtime.sendMessage({
            type: 'psk_setup',
        });
    });

    $.when(PSK.bdDeviceUrl()).then((url) => $('#BackupDeviceUrl').val(url));
    $.when(PSK.alias()).then((alias) => $('#AuthenticatorAlias').val(alias));

    $('#Recovery').on('click', function(evt: Event) {
        evt.preventDefault();
        chrome.runtime.sendMessage({
            type: 'psk_recovery',
        });
    });

    $('#SaveOptions').on('click', function(evt: Event) {
        evt.preventDefault();
        chrome.runtime.sendMessage({
            type: 'psk_options',
            url: $('#BackupDeviceUrl').val(),
            alias: $('#AuthenticatorAlias').val(),
        });
    });
});

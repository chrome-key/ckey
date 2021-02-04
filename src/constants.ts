export const keyExportFormat = 'pkcs8';
export const ivLength = 12;
export const saltLength = 16;

export const disabledIcons = {
    16: 'images/lock-16.png',
    32: 'images/lock-32.png',
    48: 'images/lock-48.png',
    128: 'images/lock-128.png',
};

export const enabledIcons = {
    16: 'images/lock_enabled-16.png',
    32: 'images/lock_enabled-32.png',
    48: 'images/lock_enabled-48.png',
    128: 'images/lock_enabled-128.png',
};

export const ES256_COSE = -7;
export const ES256 = 'P-256';
export const SHA256_COSE = 1;

export const PIN = 'pin';
export const PSK_EXTENSION_IDENTIFIER = 'PSK';
export const BACKUP_KEY = 'backup_key';
export const BD_ENDPOINT = 'bd_endpoint';
export const DEFAULT_BD_ENDPOINT = 'http://localhost:8005';
export const RECOVERY_KEY = 'recovery_key';
export const BD_TIMEOUT = 60 * 1000 * 10; // 10 minutes
export const BD = 'bd'

import { getLogger } from './logging';
import { webauthnParse, webauthnStringify } from './utils';

const log = getLogger('inject_webauthn');

(() => {
  const webauthnCallbacks = {};
  let webauthnReqCounter = 0;
  const nativeCredentials = {
    create: navigator.credentials.create,
    get: navigator.credentials.get,
  };
  const cKeyCredentials: any = {};
  cKeyCredentials.create = async (options: CredentialCreationOptions): Promise<Credential | null> => {
    const requestID = ++webauthnReqCounter;
    const registerRequest = {
      options: webauthnStringify(options),
      requestID,
      type: 'create',
    };
    const cb: Promise<any> = new Promise((res, _) => {
      webauthnCallbacks[requestID] = res;
    });
    window.postMessage(registerRequest, window.location.origin);
    const webauthnResponse = await cb;
    // Because "options" contains functions we must stringify it, otherwise
    // object cloning is illegal.
    const credential = webauthnParse(webauthnResponse.resp.credential);
    credential.getClientExtensionResults = () => ({});
    credential.__proto__ = window['PublicKeyCredential'].prototype;
    return credential;
  };
  cKeyCredentials.get = async (options?: CredentialRequestOptions): Promise<Credential | null | any> => {
    const requestID = ++webauthnReqCounter;
    const cb: Promise<any> = new Promise((res, _) => {
      webauthnCallbacks[requestID] = res;
    });

    const signRequest = {
      options: webauthnStringify(options),
      requestID,
      type: 'sign',
    };
    window.postMessage(signRequest, window.location.origin);
    const webauthnResponse = await cb;
    const credential = webauthnParse(webauthnResponse.resp.credential);
    credential.getClientExtensionResults = () => ({});
    credential.__proto__ = window['PublicKeyCredential'].prototype;
    return credential;
  };

  const hybridCredentials = {
    async create(options) {
      log.debug('created called');
      const credentialBackends = [
        cKeyCredentials,
      ];
      if (nativeCredentials.create) {
        credentialBackends.push(nativeCredentials);
      }

      // We need to bind to the "navigator.credentials" object otherwise
      // the browser will be sad.
      return Promise.race(credentialBackends.map((b) => b.create.bind(navigator.credentials)(options)));
    },
    async get(options) {
      log.debug('get called', options);
      const credentialBackends = [
        cKeyCredentials,
      ];
      if (nativeCredentials.create) {
        credentialBackends.push(nativeCredentials);
      }
      // We need to bind to the "navigator.credentials" object otherwise
      // the browser will be sad.
      return Promise.race(credentialBackends.map((b) => b.get.bind(navigator.credentials)(options)));
    },
  };

  Object.assign(navigator.credentials, hybridCredentials);
  window.addEventListener('message', (evt) => {
    const msg = evt.data;
    if (['create_response', 'sign_response'].indexOf(msg.type) > -1) {
      log.debug('relevant message', msg);
      if (msg.requestID && msg.resp && webauthnCallbacks[msg.requestID]) {
        webauthnCallbacks[msg.requestID](msg);
        delete (webauthnCallbacks[msg.requestID]);
      }
    }
  }, true);
  log.debug('injected');
})();

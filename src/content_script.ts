/* global chrome */

const webauthnInject = document.createElement('script');
webauthnInject.type = 'text/javascript';
webauthnInject.src = 'chrome-extension://' + chrome.runtime.id + '/js/inject_webauthn.js';
document.documentElement.appendChild(webauthnInject);

const relevantEventTypes = ['create_credential', 'get_credential'];

window.addEventListener('message', (event) => {
  // We only accept messages from this window to itself, no iframes allowed.
  if (event.source !== window) {
    return;
  }

  // Relay relevant messages only.
  if (event.data.type && relevantEventTypes.indexOf(event.data.type) > -1) {
    chrome.runtime.sendMessage(event.data, (resp: any) => {
      // The callback function will relay the extension response to the window object.
      window.postMessage({
        requestID: resp.requestID,
        resp,
        type: resp.type,
      }, window.location.origin);
    });
  }
}, false);

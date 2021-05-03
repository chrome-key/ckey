**OBSOLETE! This project has become obsolete with new improvements brought by Chrome 87. Chrome DevTools now provide a similar feature to what this project aimed at providing. See https://developer.chrome.com/blog/new-in-devtools-87/#webauthn**

# Chrome Key

This is a Chrome Extension that emulates a hardware authentication device, allowing you to register with Webauthn-compatible websites without requiring an actual physical device.

## Disclaimer

I cannot emphasize enough that **this project by no means replaces a Hardware Authentication Device**. The use of this extension is aimed exclusively at development, testing and debugging. If you use it in a production environment, do so at your own risk. We will elaborate on the guarantees (and lack of) that this project provides on the last post of the series.

# Building

This project uses [Webpack](https://webpack.js.org/) for its building pleasures.

```bash
$ npm run build
```

Or if you're iterating quickly...

```bash
$ npm run watch
```

# Loading into the browser

You can load the project as an unpacked extension. Upon building, you may load the directory `dist/chromium/` into your browser. More details on how to do this [here](https://developer.chrome.com/extensions/getstarted).

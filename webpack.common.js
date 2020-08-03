'use strict';

const path = require('path');

module.exports = {
  entry: {
    'chromium/js/babel_polyfill.js': 'babel-polyfill',
    'chromium/js/background.js': './src/background.ts',
    'chromium/js/content_script.js': './src/content_script.ts',
    'chromium/js/inject_webauthn.js': './src/inject_webauthn.ts',
    'chromium/js/popup.js': './src/popup.ts',
    'chromium/js/option.js': './src/option.ts'
  },
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name]',
    publicPath: './'
  },
  resolve: {
    extensions: ['.ts', 'tsx', '.js'],
  },
  module: {
    strictExportPresence: true,
    rules: [{
      enforce: 'pre',
      test: /\.(ts|tsx)$/,
      include: path.resolve(__dirname, 'src'),
      exclude: /\.test\.(ts|tsx)$/,
      loader: 'tslint-loader',
    }, {
      test: /\.(js|jsx|mjs)$/,
      include: path.resolve(__dirname, 'src'),
      loader: 'babel-loader',
      options: {
        compact: true,
      },
    }, {
      test: /\.(ts|tsx)$/,
      include: path.resolve(__dirname, 'src'),
      loader: 'ts-loader',
    }, {
      test: /\.js$/,
      include: /node_modules/,
      loader: 'strip-sourcemap-loader',
    }],
  },
}

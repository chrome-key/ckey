#!/usr/bin / env node
const editJsonFile = require("edit-json-file");

const main = () => {
    const manifest = editJsonFile('dist/chromium/manifest.json');
    const { version, description } = editJsonFile('package.json').toObject();
    manifest.set('version', version);
    manifest.set('description', description);
    manifest.save();
    console.log('Manifest updated to', version);
}

main()
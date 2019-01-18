#!/usr/bin / env node
const fs = require('fs')
const path = require('path')
const zipFolder = require('zip-folder')
const editJsonFile = require("edit-json-file");

const DEST_DIR = path.join(__dirname, '../dist/chromium')

const buildZip = (src, dist, zipFilename) => {
    console.info(`Building ${zipFilename}...`)
    return new Promise((resolve, reject) => {
        zipFolder(src, path.join(dist, zipFilename), (err) => {
            if (err) {
                reject(err)
            } else {
                resolve()
            }
        })
    })
}

const main = () => {
    const pkg = editJsonFile('package.json');
    const { name, version } = pkg.toObject();
    const zipFilename = `${name}-v${version}.zip`
    buildZip(DEST_DIR, './', zipFilename)
        .then(() => console.info('OK'))
        .catch(console.err)
}

main()

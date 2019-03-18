const { promisify } = require('util');
const fs = require('fs');
const { pathExists, ensureFile, readJSON } = require('fs-extra');
const writeFile = promisify(fs.writeFile);
const path = require('path');


const FactomKeyStore = require('./factom-key-store');

async function createKeyStore(filePath, password, seed) {
    await createEmptyFile(filePath);
    const persist = getPersistFunction(filePath);
    const keyStore = new FactomKeyStore(persist, {}, password);
    await keyStore.init(password, seed);
    return keyStore;
}

async function createEmptyFile(filePath) {
    const absoluteFilePath = path.resolve(filePath);
    if (await pathExists(absoluteFilePath)) {
        throw new Error(`File ${absoluteFilePath} already exists.`);
    }
    await ensureFile(absoluteFilePath);
}

async function getKeyStore(filePath, password) {
    const storeData = await readJSON(filePath);
    const persist = getPersistFunction(filePath);
    return new FactomKeyStore(persist, storeData, password);
}

function getPersistFunction(filePath) {
    return data => writeFile(filePath, JSON.stringify(data), { mode: 0o600 });
}

module.exports = {
    createKeyStore,
    getKeyStore
};
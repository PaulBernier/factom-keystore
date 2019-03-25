const { promisify } = require('util');
const fs = require('fs');
const { pathExists, ensureFile, readJSON } = require('fs-extra');
const writeFile = promisify(fs.writeFile);
const path = require('path');

const FactomKeyStore = require('./factom-key-store');

async function createFileKeyStore(filePath, password, data) {
    await createEmptyFile(filePath);
    const persist = getPersistFunction(filePath);
    const keyStore = new FactomKeyStore({ save: persist, password });
    await keyStore.init(data, password);
    return keyStore;
}

async function createEmptyFile(filePath) {
    const absoluteFilePath = path.resolve(filePath);
    if (await pathExists(absoluteFilePath)) {
        throw new Error(`File ${absoluteFilePath} already exists.`);
    }
    await ensureFile(absoluteFilePath);
}

async function getFileKeyStore(filePath, password) {
    const storeData = await readJSON(filePath);
    const persist = getPersistFunction(filePath);
    return new FactomKeyStore({ save: persist, initialData: storeData, password });
}

function getPersistFunction(filePath) {
    return data => writeFile(filePath, JSON.stringify(data), { mode: 0o600 });
}

module.exports = {
    createFileKeyStore,
    getFileKeyStore
};

const { createStore } = require('key-store');
const { getPublicAddress,
    isValidPrivateAddress,
    isValidPublicAddress,
    seedToPrivateEcAddress,
    seedToPrivateFctAddress } = require('factom');
const { getPublicIdentityKey,
    isValidPublicIdentityKey,
    isValidPrivateIdentityKey,
    seedToSecretIdentityKey } = require('factom-identity-lib').digital;
const bip44 = require('factombip44');
const Joi = require('joi');

const EMPTY_KEY_STORE = {
    manuallyImportedKeys: {},
    seedGeneratedCounter: 0,
    keys: {}
}; 

class FactomKeyStore {
    constructor(save, initialData, password) {
        this.store = createStore(save, initialData);
        this.password = password;
    }

    async init(password, data) {
        if (this.store.getKeyIDs.length > 0) {
            throw new Error('Cannot initialize a non empty store');
        }

        const pwd = this.getPassword(password);

        const { seed, fct, ec, identity } = getInitialStoreData(data);

        await Promise.all([
            this.store.saveKey('seed', pwd, seed, { version: 1, creationDate: Date.now() }),
            this.store.saveKey('fct', pwd, fct),
            this.store.saveKey('ec', pwd, ec),
            this.store.saveKey('identity', pwd, identity)]);
    }

    setPassword(password) {
        this.password = password;
    }

    getPassword(password) {
        const pwd = password || this.password;
        if (!pwd) {
            throw new Error('No password available');
        }
        return pwd;
    }

    getSeed(password) {
        const pwd = this.getPassword(password);
        return this.store.getPrivateKeyData('seed', pwd);
    }

    getBackup(password) {
        const pwd = this.getPassword(password);
        const backup = {};

        backup.version = 1;
        backup.seed = this.store.getPrivateKeyData('seed', pwd);
        backup.ec = this.store.getPrivateKeyData('ec', pwd);
        backup.fct = this.store.getPrivateKeyData('fct', pwd);
        backup.identity = this.store.getPrivateKeyData('identity', pwd);

        return backup;
    }

    async import(secret, password) {
        const pwd = this.getPassword(password);

        if (isValidPrivateAddress(secret)) {
            if (secret[0] === 'E') {
                return importKey(this.store, pwd, 'ec', { public: getPublicAddress(secret), secret });
            } else {
                return importKey(this.store, pwd, 'fct', { public: getPublicAddress(secret), secret });
            }
        } else if (isValidPrivateIdentityKey(secret)) {
            return importKey(this.store, pwd, 'identity', { public: getPublicIdentityKey(secret), secret });
        } else {
            throw new Error('Invalid secret: cannot import');
        }
    }

    getSecretKey(pub, password) {
        const pwd = this.getPassword(password);

        if (isValidPublicAddress(pub)) {
            if (pub[0] === 'E') {
                const keyStore = this.store.getPrivateKeyData('ec', pwd);
                return keyStore.keys[pub];
            } else {
                const keyStore = this.store.getPrivateKeyData('fct', pwd);
                return keyStore.keys[pub];
            }
        } else if (isValidPublicIdentityKey(pub)) {
            const keyStore = this.store.getPrivateKeyData('identity', pwd);
            return keyStore.keys[pub];
        } else {
            throw new Error('Invalid public key: cannot retrieve secret');
        }
    }

    getAllFactoidAddresses(password) {
        const pwd = this.getPassword(password);
        return Object.keys(this.store.getPrivateKeyData('fct', pwd).keys);
    }

    getAllEntryCreditAddresses(password) {
        const pwd = this.getPassword(password);
        return Object.keys(this.store.getPrivateKeyData('ec', pwd).keys);
    }

    getAllIdentityKeys(password) {
        const pwd = this.getPassword(password);
        return (this.store.getPrivateKeyData('identity', pwd).keys);
    }

    async generateFactoidAddress(password) {
        const pwd = this.getPassword(password);
        return generateKey({
            store: this.store,
            pwd, type: 'fct',
            seed: this.getSeed(),
            secretToPub: getPublicAddress,
            seedToHumanReadable: seedToPrivateFctAddress,
            generateFn: 'generateFactoidPrivateKey'
        });
    }

    async generateEntryCreditAddress(password) {
        const pwd = this.getPassword(password);
        return generateKey({
            store: this.store,
            pwd, type: 'ec',
            seed: this.getSeed(),
            secretToPub: getPublicAddress,
            seedToHumanReadable: seedToPrivateEcAddress,
            generateFn: 'generateEntryCreditPrivateKey'
        });
    }

    async generateIdentityKey(password) {
        const pwd = this.getPassword(password);
        return generateKey({
            store: this.store,
            pwd, type: 'identity',
            seed: this.getSeed(),
            secretToPub: getPublicIdentityKey,
            seedToHumanReadable: seedToSecretIdentityKey,
            generateFn: 'generateIdentityPrivateKey'
        });
    }
}

function importKey(store, password, type, key) {
    const keyStore = store.getPrivateKeyData(type, password);

    keyStore.manuallyImportedKeys[key.public] = true;
    keyStore.keys[key.public] = key.secret;

    return store.saveKey(type, password, keyStore);
}

async function generateKey({ store, pwd, seed, type, secretToPub, seedToHumanReadable, generateFn }) {
    // Read
    const keyStore = store.getPrivateKeyData(type, pwd);
    const counter = keyStore.seedGeneratedCounter;

    // Generate
    const generator = new bip44.FactomBIP44(seed);
    const secret = seedToHumanReadable(generator[generateFn](0, 0, counter));
    const pub = secretToPub(secret);

    // Write
    keyStore.seedGeneratedCounter++;
    keyStore.keys[pub] = secret;
    await store.saveKey(type, pwd, keyStore);

    return {
        public: pub, secret
    };
}

function getInitialStoreData(data) {
    let seed,
        ec = EMPTY_KEY_STORE,
        fct = EMPTY_KEY_STORE,
        identity = EMPTY_KEY_STORE;

    if (!data) {
        seed = bip44.randomMnemonic();
    } else if (typeof data === 'string') {
        if (bip44.validMnemonic(data)) {
            seed = data;
        } else {
            throw new Error(`Invalid mnemonic seed provided: ${data}`);
        }
    } else if (typeof data === 'object') {
        return getBackupData(data);
    } else {
        throw new Error('Invalid initialization data');
    }

    return { seed, ec, fct, identity };
}

const KEY_STORE_SCHEMA = Joi.object().keys({
    manuallyImportedKeys: Joi.object().required(),
    seedGeneratedCounter: Joi.number().integer().min(0),
    keys: Joi.object().required()
});

const BACKUP_V1_SCHEMA = Joi.object().keys({
    version: Joi.any().valid(1),
    seed: Joi.string().required(),
    ec: KEY_STORE_SCHEMA.required(),
    fct: KEY_STORE_SCHEMA.required(),
    identity: KEY_STORE_SCHEMA.required()
});

function getBackupData(backup) {
    if (backup.version === 1) {
        const validation = Joi.validate(backup, BACKUP_V1_SCHEMA);
        if (validation.error) {
            throw new Error(validation.error);
        }
        return backup;
    } else {
        throw new Error(`Unsupported backup version: ${backup}`);
    }
}

module.exports = FactomKeyStore;
const { createStore } = require('./key-store');
const {
    getPublicAddress,
    isValidPrivateAddress,
    isValidPublicAddress,
    seedToPrivateEcAddress,
    seedToPrivateFctAddress
} = require('factom');
const {
    getPublicIdentityKey,
    isValidPublicIdentityKey,
    isValidSecretIdentityKey,
    seedToSecretIdentityKey
} = require('factom-identity-lib').app;
const bip39 = require('bip39');
const bip44 = require('factombip44');
const Joi = require('joi');

const EMPTY_KEY_STORE = {
    manuallyImportedKeys: {},
    seedGeneratedCounter: 0,
    keys: {}
};

const NOOP = async () => {};

class FactomKeyStore {
    constructor(arg) {
        const { save = NOOP, initialData, password } = arg || {};
        this.store = createStore(save, initialData);
        this.password = password;
    }

    async init(data, password) {
        if (this.store.getKeyIDs().length > 0) {
            throw new Error('Cannot initialize an already initialized key store');
        }

        const pwd = this.getPassword(password);

        const { mnemonic, fct, ec, identity } = getInitialStoreData(data);
        // TODO: use mnemonicToSeedAsync when bip39 2.6.0 is released
        // https://github.com/bitcoinjs/bip39/issues/101
        const seed = bip39.mnemonicToSeedHex(mnemonic);
        this.hdWallet = new bip44.FactomHDWallet({ seed });

        await this.store.saveKeys(pwd, [
            {
                keyID: 'mnemonic',
                privateData: mnemonic,
                publicData: { version: 1, creationDate: Date.now() }
            },
            { keyID: 'seed', privateData: seed },
            { keyID: 'fct', privateData: fct },
            { keyID: 'ec', privateData: ec },
            { keyID: 'identity', privateData: identity }
        ]);
    }

    getPassword(password) {
        const pwd = password || this.password;
        if (!pwd) {
            throw new Error('No password available');
        }
        return pwd;
    }

    getMnemonic(password) {
        const pwd = this.getPassword(password);
        return this.store.getPrivateKeyData('mnemonic', pwd);
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
        backup.mnemonic = this.store.getPrivateKeyData('mnemonic', pwd);
        backup.ec = this.store.getPrivateKeyData('ec', pwd);
        backup.fct = this.store.getPrivateKeyData('fct', pwd);
        backup.identity = this.store.getPrivateKeyData('identity', pwd);

        return backup;
    }

    async import(secret, password) {
        const pwd = this.getPassword(password);

        if (isValidPrivateAddress(secret)) {
            if (secret[0] === 'E') {
                return importKey(this.store, pwd, 'ec', {
                    public: getPublicAddress(secret),
                    secret
                });
            } else {
                return importKey(this.store, pwd, 'fct', {
                    public: getPublicAddress(secret),
                    secret
                });
            }
        } else if (isValidSecretIdentityKey(secret)) {
            return importKey(this.store, pwd, 'identity', {
                public: getPublicIdentityKey(secret),
                secret
            });
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
        return Object.keys(this.store.getPrivateKeyData('identity', pwd).keys);
    }

    async generateFactoidAddress(password) {
        const pwd = this.getPassword(password);
        return generateKey.call(this, {
            pwd,
            type: 'fct',
            secretToPub: getPublicAddress,
            seedToHumanReadable: seedToPrivateFctAddress,
            generateFn: 'generateFactoidPrivateKey'
        });
    }

    async generateEntryCreditAddress(password) {
        const pwd = this.getPassword(password);
        return generateKey.call(this, {
            pwd,
            type: 'ec',
            secretToPub: getPublicAddress,
            seedToHumanReadable: seedToPrivateEcAddress,
            generateFn: 'generateEntryCreditPrivateKey'
        });
    }

    async generateIdentityKey(password) {
        const pwd = this.getPassword(password);
        return generateKey.call(this, {
            pwd,
            type: 'identity',
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

async function generateKey({ pwd, type, secretToPub, seedToHumanReadable, generateFn }) {
    // Lazy loading of HDWallet
    if (!this.hdWallet) {
        this.hdWallet = new bip44.FactomHDWallet({ seed: this.getSeed(pwd) });
    }

    // Read
    const keyStore = this.store.getPrivateKeyData(type, pwd);
    const counter = keyStore.seedGeneratedCounter;

    // Generate
    const secret = seedToHumanReadable(this.hdWallet[generateFn](0, 0, counter));
    const pub = secretToPub(secret);

    // Write
    keyStore.seedGeneratedCounter++;
    keyStore.keys[pub] = secret;
    await this.store.saveKey(type, pwd, keyStore);

    return {
        public: pub,
        secret
    };
}

function getInitialStoreData(data) {
    let mnemonic,
        ec = EMPTY_KEY_STORE,
        fct = EMPTY_KEY_STORE,
        identity = EMPTY_KEY_STORE;

    if (!data) {
        mnemonic = bip44.randomMnemonic();
    } else if (typeof data === 'string') {
        if (bip44.validMnemonic(data)) {
            mnemonic = data;
        } else {
            throw new Error(`Invalid mnemonic seed provided: ${data}`);
        }
    } else if (typeof data === 'object') {
        return getBackupData(data);
    } else {
        throw new Error('Invalid initialization data');
    }

    return { mnemonic, ec, fct, identity };
}

const KEY_STORE_SCHEMA = Joi.object().keys({
    manuallyImportedKeys: Joi.object().required(),
    seedGeneratedCounter: Joi.number()
        .integer()
        .min(0),
    keys: Joi.object().required()
});

const BACKUP_V1_SCHEMA = Joi.object().keys({
    version: Joi.any().valid(1),
    mnemonic: Joi.string().required(),
    seed: Joi.string().required(),
    ec: KEY_STORE_SCHEMA.required(),
    fct: KEY_STORE_SCHEMA.required(),
    identity: KEY_STORE_SCHEMA.required()
});

function getBackupData(backup) {
    if (backup.version === 1) {
        Joi.assert(backup, BACKUP_V1_SCHEMA);
        return backup;
    } else {
        throw new Error(`Unsupported backup version: ${backup}`);
    }
}

module.exports = FactomKeyStore;

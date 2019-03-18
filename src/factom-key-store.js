const { createStore } = require('key-store');
const { isValidPrivateAddress, getPublicAddress, isValidPublicAddress } = require('factom');
const bip44 = require('factombip44');

const KEY_STORE_SCHEMA = {
    'public-keys': {},
    'manually-imported-keys': {},
    'seed-generated-counter': 0,
    'keys': {}
};

class FactomKeyStore {
    constructor(save, initialData, password) {
        this.store = createStore(save, initialData);
        this.password = password;
    }

    async init(password, userSeed) {
        if (this.store.getKeyIDs.length > 0) {
            throw new Error('Cannot initialize a non empty store');
        }

        let seed = userSeed;
        if (!seed) {
            seed = bip44.randomMnemonic();
        } else if (bip44.validMnemonic(seed)) {
            throw new Error(`Invalid mnemonic seed provided: ${userSeed}`);
        }

        const pwd = this.getPassword(password);

        await Promise.all([
            this.store.saveKey('seed', pwd, seed),
            this.store.saveKey('fct-store', pwd, KEY_STORE_SCHEMA),
            this.store.saveKey('ec-store', pwd, KEY_STORE_SCHEMA),
            this.store.saveKey('identity-store', pwd, KEY_STORE_SCHEMA)]);
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

    async import(secret, password) {
        const pwd = this.getPassword(password);

        if (isValidPrivateAddress(secret)) {
            if (secret[0] === 'E') {
                return importKey(this.store, pwd, 'ec', { public: getPublicAddress(secret), secret });
            } else {
                return importKey(this.store, pwd, 'fct', { public: getPublicAddress(secret), secret });
            }
        }
    }

    getSecretKey(pub, password) {
        const pwd = this.getPassword(password);

        if (isValidPublicAddress(pub)) {
            if (pub[0] === 'E') {
                const keyStore = this.store.getPrivateKeyData('ec-store', pwd);
                return keyStore.keys[pub];
            } else {
                const keyStore = this.store.getPrivateKeyData('fct-store', pwd);
                return keyStore.keys[pub];
            }
        }
    }
}

function importKey(store, password, type, key) {
    const keyStore = store.getPrivateKeyData(`${type}-store`, password);

    keyStore['manually-imported-keys'][key.public] = true;
    keyStore['public-keys'][key.public] = true;
    keyStore.keys[key.public] = key.secret;

    return store.saveKey(`${type}-store`, password, keyStore);
}

module.exports = FactomKeyStore;
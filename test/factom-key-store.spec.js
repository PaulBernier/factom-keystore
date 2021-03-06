const assert = require('chai').assert,
    bip44 = require('factombip44'),
    { seedToPrivateEcAddress, seedToPrivateFctAddress } = require('factom'),
    { seedToSecretIdentityKey } = require('factom-identity-lib').app,
    FactomKeyStore = require('../src/factom-key-store');

const PWD = 'password';

describe('FactomKeyStore', function() {
    it('Should initialize new key store without password', async function() {
        const ks = new FactomKeyStore();
        await ks.init(undefined, PWD);

        assert.isTrue(bip44.validMnemonic(ks.getMnemonic(PWD)));
        assert.isNotEmpty(ks.getSeed(PWD));
        assert.isEmpty(ks.getAllEntryCreditAddresses(PWD));
        assert.isEmpty(ks.getAllFactoidAddresses(PWD));
        assert.isEmpty(ks.getAllIdentityKeys(PWD));
    });

    it('Should initialize new key store with password', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        await ks.init();

        assert.isTrue(bip44.validMnemonic(ks.getMnemonic()));
        assert.isNotEmpty(ks.getSeed(PWD));
        assert.isEmpty(ks.getAllEntryCreditAddresses());
        assert.isEmpty(ks.getAllFactoidAddresses());
        assert.isEmpty(ks.getAllIdentityKeys());
    });

    it('Should initialize new key store with 12-word seed', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        await ks.init(128);

        assert.isTrue(bip44.validMnemonic(ks.getMnemonic()));
        assert.lengthOf(ks.getMnemonic().split(' '), 12);
    });

    it('Should initialize new key store with 24-word seed', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        await ks.init(256);

        assert.isTrue(bip44.validMnemonic(ks.getMnemonic()));
        assert.lengthOf(ks.getMnemonic().split(' '), 24);
    });

    it('Should initialize key store with seed', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        const mnemonic = bip44.randomMnemonic();
        await ks.init(mnemonic);

        assert.strictEqual(ks.getMnemonic(), mnemonic);
        assert.isNotEmpty(ks.getSeed(PWD));
        assert.isEmpty(ks.getAllEntryCreditAddresses());
        assert.isEmpty(ks.getAllFactoidAddresses());
        assert.isEmpty(ks.getAllIdentityKeys());
    });

    it('Should reject invalid seed', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        try {
            await ks.init(
                'yolo yellow yellow yellow yellow yellow yellow yellow yellow yellow yellow yellow'
            );
        } catch (e) {
            return assert.instanceOf(e, Error);
        }
        throw new Error('Should have thrown');
    });

    it('Should fail to init an already initialized key store', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        await ks.init();
        try {
            await ks.init();
        } catch (e) {
            return assert.instanceOf(e, Error);
        }
        throw new Error('Should have thrown');
    });

    it('Should import backup v1', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        const backup = require('./backup-v1.json');
        await ks.init(backup);

        const fctAddresses = ks.getAllFactoidAddresses();
        const ecAddresses = ks.getAllEntryCreditAddresses();
        const identityKeys = ks.getAllIdentityKeys();

        assert.strictEqual(ks.getMnemonic(), backup.mnemonic);
        assert.strictEqual(ks.getSeed(), backup.seed);
        assert.lengthOf(fctAddresses, 1);
        assert.lengthOf(ecAddresses, 1);
        assert.lengthOf(identityKeys, 2);
        assert.isDefined(ks.getSecretKey('EC2asvKT6TyUEqYe4uGCAc7xY5HvcwGQwjmL5ku8ra2wE2E4xicL'));
        assert.isDefined(ks.getSecretKey('FA32mpZSbGipZxPeVmr6S2SnGix2MypE4vdh9bsc7f5Sm86aTYaK'));
        assert.isDefined(
            ks.getSecretKey('idpub1p5K8XqqGD9jZxXaaznJEWFzcQC54d9RGRu4NWyoWdM5nV6Rm8')
        );
        assert.isDefined(
            ks.getSecretKey('idpub1p5K8XqqGD9jZxXaaznJEWFzcQC54d9RGRu4NWyoWdM5nV6Rm8')
        );

        const generator = new bip44.FactomHDWallet({ seed: backup.seed });
        const fctAddress = await ks.generateFactoidAddress();
        const ecAddress = await ks.generateEntryCreditAddress();
        const identityKey = await ks.generateIdentityKey();

        assert.strictEqual(
            fctAddress.secret,
            seedToPrivateFctAddress(generator.generateFactoidPrivateKey(0, 0, 1))
        );
        assert.strictEqual(
            ecAddress.secret,
            seedToPrivateEcAddress(generator.generateEntryCreditPrivateKey(0, 0, 1))
        );
        assert.strictEqual(
            identityKey.secret,
            seedToSecretIdentityKey(generator.generateIdentityPrivateKey(0, 0, 1))
        );
    });

    it('Should get password', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        await ks.init();

        assert.strictEqual(ks.getPassword(), PWD);
        assert.strictEqual(ks.getPassword('other-password'), 'other-password');
    });

    it('Should throw when no password available', async function() {
        const ks = new FactomKeyStore();

        assert.throws(() => ks.getPassword(), Error);
    });

    it('Should get undefined secret key', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        await ks.init();

        assert.isUndefined(
            ks.getSecretKey('idpub1p5K8XqqGD9jZxXaaznJEWFzcQC54d9RGRu4NWyoWdM5nV6Rm8')
        );
    });

    it('Should throw on invalid public key', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        await ks.init();

        assert.throws(() => ks.getSecretKey('not a public key'));
    });

    it('Should generate Factoid address', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        const mnemonic = bip44.randomMnemonic();
        await ks.init(mnemonic);

        const address = await ks.generateFactoidAddress();

        const generator = new bip44.FactomHDWallet({ mnemonic });
        const factoidAddresses = ks.getAllFactoidAddresses();
        const secretKey = ks.getSecretKey(address.public);
        assert.lengthOf(factoidAddresses, 1);
        assert.strictEqual(factoidAddresses[0], address.public);
        assert.strictEqual(secretKey, address.secret);
        assert.strictEqual(
            secretKey,
            seedToPrivateFctAddress(generator.generateFactoidPrivateKey(0, 0, 0))
        );
    });

    it('Should generate multiple Factoid addresses', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        const mnemonic = bip44.randomMnemonic();
        await ks.init(mnemonic);

        const addresses = await ks.generateFactoidAddress(3);
        const addresses2 = await ks.generateFactoidAddress();

        const generator = new bip44.FactomHDWallet({ mnemonic });
        const factoidAddresses = ks.getAllFactoidAddresses();
        assert.lengthOf(addresses, 3);
        assert.lengthOf(factoidAddresses, 4);
        assert.includeDeepMembers(factoidAddresses, [
            addresses2.public,
            ...addresses.map(a => a.public)
        ]);

        const secretKey = ks.getSecretKey(addresses2.public);
        assert.strictEqual(secretKey, addresses2.secret);
        assert.strictEqual(
            secretKey,
            seedToPrivateFctAddress(generator.generateFactoidPrivateKey(0, 0, 3))
        );
    });

    it('Should generate Entry Credit address', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        const mnemonic = bip44.randomMnemonic();
        await ks.init(mnemonic);

        const address = await ks.generateEntryCreditAddress();

        const generator = new bip44.FactomHDWallet({ mnemonic });
        const ecAddresses = ks.getAllEntryCreditAddresses();
        const secretKey = ks.getSecretKey(address.public);
        assert.lengthOf(ecAddresses, 1);
        assert.strictEqual(ecAddresses[0], address.public);
        assert.strictEqual(secretKey, address.secret);
        assert.strictEqual(
            secretKey,
            seedToPrivateEcAddress(generator.generateEntryCreditPrivateKey(0, 0, 0))
        );
    });

    it('Should generate multiple Entry Credit addresses', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        const mnemonic = bip44.randomMnemonic();
        await ks.init(mnemonic);

        const addresses = await ks.generateEntryCreditAddress(3);
        const addresses2 = await ks.generateEntryCreditAddress();

        const generator = new bip44.FactomHDWallet({ mnemonic });
        const factoidAddresses = ks.getAllEntryCreditAddresses();
        assert.lengthOf(addresses, 3);
        assert.lengthOf(factoidAddresses, 4);
        assert.includeDeepMembers(factoidAddresses, [
            addresses2.public,
            ...addresses.map(a => a.public)
        ]);

        const secretKey = ks.getSecretKey(addresses2.public);
        assert.strictEqual(secretKey, addresses2.secret);
        assert.strictEqual(
            secretKey,
            seedToPrivateEcAddress(generator.generateEntryCreditPrivateKey(0, 0, 3))
        );
    });

    it('Should generate Entry Credit address', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        const mnemonic = bip44.randomMnemonic();
        await ks.init(mnemonic);

        const idKey = await ks.generateIdentityKey();

        const generator = new bip44.FactomHDWallet({ mnemonic });
        const identityKeys = ks.getAllIdentityKeys();
        const secretKey = ks.getSecretKey(idKey.public);
        assert.lengthOf(identityKeys, 1);
        assert.strictEqual(identityKeys[0], idKey.public);
        assert.strictEqual(secretKey, idKey.secret);
        assert.strictEqual(
            secretKey,
            seedToSecretIdentityKey(generator.generateIdentityPrivateKey(0, 0, 0))
        );
    });

    it('Should generate multiple Identity keys', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        const mnemonic = bip44.randomMnemonic();
        await ks.init(mnemonic);

        const addresses = await ks.generateIdentityKey(3);
        const addresses2 = await ks.generateIdentityKey();

        const generator = new bip44.FactomHDWallet({ mnemonic });
        const factoidAddresses = ks.getAllIdentityKeys();
        assert.lengthOf(addresses, 3);
        assert.lengthOf(factoidAddresses, 4);
        assert.includeDeepMembers(factoidAddresses, [
            addresses2.public,
            ...addresses.map(a => a.public)
        ]);

        const secretKey = ks.getSecretKey(addresses2.public);
        assert.strictEqual(secretKey, addresses2.secret);
        assert.strictEqual(
            secretKey,
            seedToSecretIdentityKey(generator.generateIdentityPrivateKey(0, 0, 3))
        );
    });

    it('Should increment seed counter', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        const mnemonic = bip44.randomMnemonic();
        await ks.init(mnemonic);

        await ks.generateFactoidAddress();
        await ks.generateFactoidAddress();
        const address = await ks.generateFactoidAddress();

        const generator = new bip44.FactomHDWallet({ mnemonic });
        const factoidAddresses = ks.getAllFactoidAddresses();
        const secretKey = ks.getSecretKey(address.public);
        assert.lengthOf(factoidAddresses, 3);
        assert.strictEqual(secretKey, address.secret);
        assert.strictEqual(
            address.secret,
            seedToPrivateFctAddress(generator.generateFactoidPrivateKey(0, 0, 2))
        );
    });

    it('Should reject invalid import', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        await ks.init();

        try {
            await ks.import('not supported');
        } catch (e) {
            return assert.instanceOf(e, Error);
        }
        throw new Error('Should have thrown');
    });

    it('Should import Factoid address', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        await ks.init();

        await ks.import('Fs1wZau1YNto1xCVkELULUHiKaD14LKVTceVdvWEr9PwEDCACCDr');

        const allPublicKeys = ks.getAllFactoidAddresses();
        const secretKey = ks.getSecretKey('FA33sHHzz1ufCeDJav4SXAKWocsZpJSLffqEXScoADFn3srS6ttM');
        assert.include(allPublicKeys, 'FA33sHHzz1ufCeDJav4SXAKWocsZpJSLffqEXScoADFn3srS6ttM');
        assert.strictEqual(secretKey, 'Fs1wZau1YNto1xCVkELULUHiKaD14LKVTceVdvWEr9PwEDCACCDr');
    });

    it('Should import Entry Credit address', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        await ks.init();

        await ks.import('Es3nSPRJoiJcN6U7oX3PMjYBB8R4QBnp3iud9M8S1UQZhn3i1m8T');

        const allPublicKeys = ks.getAllEntryCreditAddresses();
        const secretKey = ks.getSecretKey('EC2UBa4yF51DCGko9AS2piSesMWuAJAFnGu6YYoXJ2zjmkts1xAK');
        assert.include(allPublicKeys, 'EC2UBa4yF51DCGko9AS2piSesMWuAJAFnGu6YYoXJ2zjmkts1xAK');
        assert.strictEqual(secretKey, 'Es3nSPRJoiJcN6U7oX3PMjYBB8R4QBnp3iud9M8S1UQZhn3i1m8T');
    });

    it('Should import Identity key', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        await ks.init();

        await ks.import('idsec1B5cDbNNB4s1cQSZt24u3j1QtB5DsjFyBSmXqpUs645fJ3ot9C');

        const allPublicKeys = ks.getAllIdentityKeys();
        const secretKey = ks.getSecretKey(
            'idpub1p5K8XqqGD9jZxXaaznJEWFzcQC54d9RGRu4NWyoWdM5nV6Rm8'
        );
        assert.include(allPublicKeys, 'idpub1p5K8XqqGD9jZxXaaznJEWFzcQC54d9RGRu4NWyoWdM5nV6Rm8');
        assert.strictEqual(secretKey, 'idsec1B5cDbNNB4s1cQSZt24u3j1QtB5DsjFyBSmXqpUs645fJ3ot9C');
    });

    it('Should get backup v1', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        const mnemonic = bip44.randomMnemonic();
        await ks.init(mnemonic);

        await ks.import('idsec1B5cDbNNB4s1cQSZt24u3j1QtB5DsjFyBSmXqpUs645fJ3ot9C');
        const ecAddress = await ks.generateEntryCreditAddress();
        const fctAddress = await ks.generateFactoidAddress();
        const idKey = await ks.generateIdentityKey();

        const backup = ks.getBackup();

        assert.strictEqual(backup.version, 1);
        assert.strictEqual(backup.mnemonic, mnemonic);

        const fctKeys = {};
        fctKeys[fctAddress.public] = fctAddress.secret;
        assert.deepStrictEqual(backup.fct.keys, fctKeys);
        assert.isEmpty(backup.fct.manuallyImportedKeys);

        const ecKeys = {};
        ecKeys[ecAddress.public] = ecAddress.secret;
        assert.deepStrictEqual(backup.ec.keys, ecKeys);
        assert.isEmpty(backup.ec.manuallyImportedKeys);

        const idKeys = {};
        idKeys[idKey.public] = idKey.secret;
        idKeys['idpub1p5K8XqqGD9jZxXaaznJEWFzcQC54d9RGRu4NWyoWdM5nV6Rm8'] =
            'idsec1B5cDbNNB4s1cQSZt24u3j1QtB5DsjFyBSmXqpUs645fJ3ot9C';
        assert.deepStrictEqual(backup.identity.keys, idKeys);
        assert.lengthOf(Object.keys(backup.identity.manuallyImportedKeys), 1);
        assert.isTrue(
            backup.identity.manuallyImportedKeys[
                'idpub1p5K8XqqGD9jZxXaaznJEWFzcQC54d9RGRu4NWyoWdM5nV6Rm8'
            ]
        );
    });

    it('Should change password', async function() {
        const ks = new FactomKeyStore({ password: PWD });
        await ks.init();

        await ks.import('Fs1wZau1YNto1xCVkELULUHiKaD14LKVTceVdvWEr9PwEDCACCDr');
        await ks.import('Es3nSPRJoiJcN6U7oX3PMjYBB8R4QBnp3iud9M8S1UQZhn3i1m8T');
        await ks.changePassword(PWD, 'new_password');

        assert.strictEqual(ks.getPassword(), 'new_password');
        assert.isString(ks.store.getPrivateKeyData('seed', 'new_password'));
        assert.strictEqual(
            ks.getSecretKey('FA33sHHzz1ufCeDJav4SXAKWocsZpJSLffqEXScoADFn3srS6ttM'),
            'Fs1wZau1YNto1xCVkELULUHiKaD14LKVTceVdvWEr9PwEDCACCDr'
        );
        assert.strictEqual(
            ks.getSecretKey('EC2UBa4yF51DCGko9AS2piSesMWuAJAFnGu6YYoXJ2zjmkts1xAK'),
            'Es3nSPRJoiJcN6U7oX3PMjYBB8R4QBnp3iud9M8S1UQZhn3i1m8T'
        );
    });
});

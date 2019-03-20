# factom-keystore

Store for Factom secrets. Originally created to be used in the [FAT wallet](https://github.com/Factom-Asset-Tokens/wallet).

It supports encrypted storage of:
* Factoid addresses
* Entry Credit addresses
* Digital Identity keys

Secrets can either be imported or generated from a 12-word mnemonic seed.

## Security

Secrets are encrypted at rest and in memory using the authenticated encryption algorithm *xsalsa20-poly1305*. We use the implementation of `tweetnacl-js` which has been [formally audited](https://github.com/dchest/tweetnacl-js#audits).
'use strict';
var __assign =
    (this && this.__assign) ||
    Object.assign ||
    function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
        }
        return t;
    };
var __awaiter =
    (this && this.__awaiter) ||
    function(thisArg, _arguments, P, generator) {
        return new (P || (P = Promise))(function(resolve, reject) {
            function fulfilled(value) {
                try {
                    step(generator.next(value));
                } catch (e) {
                    reject(e);
                }
            }
            function rejected(value) {
                try {
                    step(generator['throw'](value));
                } catch (e) {
                    reject(e);
                }
            }
            function step(result) {
                result.done
                    ? resolve(result.value)
                    : new P(function(resolve) {
                          resolve(result.value);
                      }).then(fulfilled, rejected);
            }
            step((generator = generator.apply(thisArg, _arguments || [])).next());
        });
    };
var __generator =
    (this && this.__generator) ||
    function(thisArg, body) {
        var _ = {
                label: 0,
                sent: function() {
                    if (t[0] & 1) throw t[1];
                    return t[1];
                },
                trys: [],
                ops: []
            },
            f,
            y,
            t,
            g;
        return (
            (g = { next: verb(0), throw: verb(1), return: verb(2) }),
            typeof Symbol === 'function' &&
                (g[Symbol.iterator] = function() {
                    return this;
                }),
            g
        );
        function verb(n) {
            return function(v) {
                return step([n, v]);
            };
        }
        function step(op) {
            if (f) throw new TypeError('Generator is already executing.');
            while (_)
                try {
                    if (
                        ((f = 1),
                        y &&
                            (t =
                                op[0] & 2
                                    ? y['return']
                                    : op[0]
                                    ? y['throw'] || ((t = y['return']) && t.call(y), 0)
                                    : y.next) &&
                            !(t = t.call(y, op[1])).done)
                    )
                        return t;
                    if (((y = 0), t)) op = [op[0] & 2, t.value];
                    switch (op[0]) {
                        case 0:
                        case 1:
                            t = op;
                            break;
                        case 4:
                            _.label++;
                            return { value: op[1], done: false };
                        case 5:
                            _.label++;
                            y = op[1];
                            op = [0];
                            continue;
                        case 7:
                            op = _.ops.pop();
                            _.trys.pop();
                            continue;
                        default:
                            if (
                                !((t = _.trys), (t = t.length > 0 && t[t.length - 1])) &&
                                (op[0] === 6 || op[0] === 2)
                            ) {
                                _ = 0;
                                continue;
                            }
                            if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) {
                                _.label = op[1];
                                break;
                            }
                            if (op[0] === 6 && _.label < t[1]) {
                                _.label = t[1];
                                t = op;
                                break;
                            }
                            if (t && _.label < t[2]) {
                                _.label = t[2];
                                _.ops.push(op);
                                break;
                            }
                            if (t[2]) _.ops.pop();
                            _.trys.pop();
                            continue;
                    }
                    op = body.call(thisArg, _);
                } catch (e) {
                    op = [6, e];
                    y = 0;
                } finally {
                    f = t = 0;
                }
            if (op[0] & 5) throw op[1];
            return { value: op[0] ? op[1] : void 0, done: true };
        }
    };
var __importStar =
    (this && this.__importStar) ||
    function(mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null)
            for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
        result['default'] = mod;
        return result;
    };
var __importDefault =
    (this && this.__importDefault) ||
    function(mod) {
        return mod && mod.__esModule ? mod : { default: mod };
    };
Object.defineProperty(exports, '__esModule', { value: true });
var sha256 = __importStar(require('fast-sha256'));
var tweetnacl_1 = __importDefault(require('tweetnacl'));
var tweetnacl_util_1 = __importDefault(require('tweetnacl-util'));
function randomNonce() {
    return tweetnacl_util_1.default.encodeBase64(
        tweetnacl_1.default.randomBytes(tweetnacl_1.default.secretbox.nonceLength)
    );
}
function deriveHashFromPassword(password, metadata) {
    return sha256.pbkdf2(
        tweetnacl_util_1.default.decodeUTF8(password),
        tweetnacl_util_1.default.decodeBase64(metadata.nonce),
        metadata.iterations,
        tweetnacl_1.default.secretbox.keyLength
    );
}
function decrypt(encryptedBase64, metadata, password) {
    var secretKey = deriveHashFromPassword(password, metadata);
    var decrypted = tweetnacl_1.default.secretbox.open(
        tweetnacl_util_1.default.decodeBase64(encryptedBase64),
        tweetnacl_util_1.default.decodeBase64(metadata.nonce),
        secretKey
    );
    if (!decrypted) {
        throw new Error('Decryption failed.');
    }
    return JSON.parse(tweetnacl_util_1.default.encodeUTF8(decrypted));
}
function encrypt(privateData, metadata, password) {
    var secretKey = deriveHashFromPassword(password, metadata);
    var data = tweetnacl_util_1.default.decodeUTF8(JSON.stringify(privateData));
    var encrypted = tweetnacl_1.default.secretbox(
        data,
        tweetnacl_util_1.default.decodeBase64(metadata.nonce),
        secretKey
    );
    return tweetnacl_util_1.default.encodeBase64(encrypted);
}
function createStore(save, initialKeys, options) {
    if (initialKeys === void 0) {
        initialKeys = {};
    }
    if (options === void 0) {
        options = {};
    }
    var _a = options.iterations,
        iterations = _a === void 0 ? 10000 : _a;
    var keysData = initialKeys;
    function _saveKey(keyID, password, privateData, publicData) {
        if (publicData === void 0) {
            publicData = {};
        }
        // Important: Do not re-use previous metadata!
        // Use a fresh nonce. Also the previous metadata might have been forged.
        var metadata = {
            nonce: randomNonce(),
            iterations: iterations
        };
        keysData[keyID] = {
            metadata: metadata,
            public: publicData,
            private: encrypt(privateData, metadata, password)
        };
    }
    return {
        getKeyIDs: function() {
            return Object.keys(keysData);
        },
        getPublicKeyData: function(keyID) {
            return keysData[keyID].public;
        },
        getPrivateKeyData: function(keyID, password) {
            return decrypt(keysData[keyID].private, keysData[keyID].metadata, password);
        },
        saveKey: function(keyID, password, privateData, publicData) {
            if (publicData === void 0) {
                publicData = {};
            }
            return __awaiter(this, void 0, void 0, function() {
                return __generator(this, function(_a) {
                    switch (_a.label) {
                        case 0:
                            _saveKey(keyID, password, privateData, publicData);
                            return [4 /*yield*/, save(keysData)];
                        case 1:
                            _a.sent();
                            return [2 /*return*/];
                    }
                });
            });
        },
        saveKeys: function(password, data) {
            return __awaiter(this, void 0, void 0, function() {
                return __generator(this, function(_a) {
                    switch (_a.label) {
                        case 0:
                            data.forEach(function(d) {
                                return _saveKey(d.keyID, password, d.privateData, d.publicData);
                            });
                            return [4 /*yield*/, save(keysData)];
                        case 1:
                            _a.sent();
                            return [2 /*return*/];
                    }
                });
            });
        },
        savePublicKeyData: function(keyID, publicData) {
            return __awaiter(this, void 0, void 0, function() {
                return __generator(this, function(_a) {
                    switch (_a.label) {
                        case 0:
                            if (!keysData[keyID]) {
                                // Prevent creating an incomplete key record
                                throw new Error(
                                    'Cannot save public data for key ' +
                                        keyID +
                                        '. Key does not yet exist in store.'
                                );
                            }
                            keysData[keyID] = __assign({}, keysData[keyID], { public: publicData });
                            return [4 /*yield*/, save(keysData)];
                        case 1:
                            _a.sent();
                            return [2 /*return*/];
                    }
                });
            });
        },
        removeKey: function(keyID) {
            return __awaiter(this, void 0, void 0, function() {
                return __generator(this, function(_a) {
                    switch (_a.label) {
                        case 0:
                            if (!keysData[keyID]) {
                                throw new Error('Cannot delete key ' + keyID + '. Key not found.');
                            }
                            delete keysData[keyID];
                            return [4 /*yield*/, save(keysData)];
                        case 1:
                            _a.sent();
                            return [2 /*return*/];
                    }
                });
            });
        }
    };
}
exports.createStore = createStore;

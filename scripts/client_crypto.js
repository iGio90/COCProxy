/**
 *
 GDumper is a free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
'use strict';

const nacl = require("sc-tweetnacl");
const Nonce = require("./nonce");
const EMsg = require('./emsg');

class Crypto {
    constructor() {
        this.publicKey = null;
        this.privateKey = null;
        this.publicServerKey = null;
        this.sessionsKey = null;
        this.decryptOutNonce = null;
        this.decryptOutInternalNonce = null;
        this.decryptInNonce = null;
        this.sharedKey = null;
        this.serverCrypto = null;
    }

    setPublicKey(publicKey) {
        this.publicKey = publicKey;
    }

    setPrivateKey(privateKey) {
        this.privateKey = privateKey;
    }

    setPublicServerKey(publicServerKey) {
        this.publicServerKey = publicServerKey;
    }

    getDecryptOutNonce() {
        return this.decryptOutNonce;
    }

    setDecryptOutNonce(nonce) {
        this.decryptOutNonce = new Nonce({ nonce: nonce });
    }

    getDecryptInNonce() {
        return this.decryptInNonce;
    }

    setDecryptInNonce(nonce) {
        this.decryptInNonce = new Nonce({ nonce: nonce });
    }

    setSharedKey(sharedKey) {
        this.sharedKey = sharedKey;
    }

    setServerCrypto(serverCrypto) {
        this.serverCrypto = serverCrypto;
    }

    decrypt(message) {
        if (message.messageType === EMsg.ClientHello) {
            message.decrypted = message.payload;
        } else if (message.messageType === EMsg.Login) {
            this.privateKey = message.payload.slice(0, 32);
            this.publicKey = nacl.scalarMult.base(this.privateKey);
            this.serverCrypto.setPublicKey(this.publicKey);
            this.serverCrypto.setPrivateKey(this.privateKey);

            let cipherText = message.payload.slice(32);
            let nonce = new Nonce({ clientKey: this.privateKey, serverKey: this.publicServerKey });
            let sharedKey = new Buffer(nacl.box.before(this.publicServerKey, this.privateKey));
            message.decrypted = nacl.box.open.after(cipherText, nonce.getBuffer(), sharedKey);
            if (message.decrypted) {
                this.sessionsKey = message.decrypted.slice(0, 24);
                this.setDecryptOutNonce(Buffer.from(message.decrypted.slice(24, 48)));
                this.decryptOutInternalNonce = new Nonce({nonce: Buffer.from(message.decrypted.slice(24, 48))})
                this.serverCrypto.setDecryptOutNonce(this.decryptOutNonce.getBuffer());
                message.decrypted = message.decrypted.slice(48);
            }
        } else {
            if (this.sharedKey === null) {
                message.decrypted = message.payload;
                return;
            }

            this.decryptOutNonce.increment();
            message.decrypted = nacl.box.open.after(message.payload,
                this.decryptOutNonce.getBuffer(), this.sharedKey);
        }
    }

    encrypt(message) {
        if (message.messageType === EMsg.Login) {
            let nonce = new Nonce({ clientKey: this.publicKey, serverKey: this.publicServerKey });
            let sharedKey = new Buffer(nacl.box.before(this.publicServerKey, this.privateKey));
            let toEncrypt = Buffer.concat([toBuffer(this.sessionsKey), this.decryptOutNonce.getBuffer(), toBuffer(message.decrypted)]);
            let encryptedPayload = nacl.box.after(toEncrypt, nonce.getBuffer(), sharedKey)
            message.encrypted = Buffer.concat([toBuffer(this.publicKey), toBuffer(encryptedPayload)]);
        } else {
            if (this.decryptOutInternalNonce !== null) {
                this.decryptOutInternalNonce.increment();
                message.encrypted = nacl.box.after(message.decrypted, this.decryptOutInternalNonce.getBuffer(), this.sharedKey)
            } else {
                message.encrypted = message.payload;
            }
        }
    }

    incrementInternal() {
        this.decryptOutInternalNonce.increment()
    }
}

function toArrayBuffer(buf) {
    var ab = new ArrayBuffer(buf.length);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buf.length; ++i) {
        view[i] = buf[i];
    }
    return ab;
}

function toBuffer(ab) {
    var buf = new Buffer(ab.byteLength);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buf.length; ++i) {
        buf[i] = view[i];
    }
    return buf;
}

module.exports = Crypto;

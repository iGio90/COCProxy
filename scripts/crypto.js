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
        this.decryptOutNonce = null;
        this.decryptInNonce = null;
        this.sharedKey = null;
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

    decrypt(message, out) {
        if (message.messageType === EMsg.Login) {
            let cipherText = message.payload.slice(32);
            let nonce = new Nonce({ clientKey: this.publicKey, serverKey: this.publicServerKey });
            let sharedKey = new Buffer(nacl.box.before(this.publicServerKey, this.privateKey));
            message.decrypted = nacl.box.open.after(cipherText, nonce.getBuffer(), sharedKey);
            if (message.decrypted) {
                this.setDecryptOutNonce(Buffer.from(message.decrypted.slice(24, 48)));
                message.decrypted = message.decrypted.slice(48);
            }
        } else if (message.messageType === 21890) {
            let nonce = new Nonce({ clientKey: this.publicKey, serverKey: this.publicServerKey, nonce: this.decryptOutNonce });

            let sharedKey = new Buffer(nacl.box.before(this.publicServerKey, this.privateKey));
            message.decrypted = nacl.box.open.after(message.payload, nonce.getBuffer(), sharedKey);

            if (message.decrypted) {
                this.setDecryptInNonce(Buffer.from(message.decrypted.slice(0, 24)));
                this.setSharedKey(Buffer.from(message.decrypted.slice(24, 56)));
                message.decrypted = message.decrypted.slice(56);
            }
        } else {
            if (out) {
                if (this.sharedKey === null) {
                    message.decrypted = message.payload;
                    return;
                }
                this.decryptOutNonce.increment();
                message.decrypted = nacl.box.open.after(message.payload,
                    this.decryptOutNonce.getBuffer(), this.sharedKey);
            } else {
                this.decryptInNonce.increment();
                message.decrypted = nacl.box.open.after(message.payload,
                    this.decryptInNonce.getBuffer(), this.sharedKey);
            }
        }
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

module.exports = Crypto;

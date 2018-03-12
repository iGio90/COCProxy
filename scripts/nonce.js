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

const blake2 = require("blake2");
const nacl = require("sc-tweetnacl");

class Nonce {
    constructor(arg) {
        if (!arg.clientKey) {
            if (arg.nonce) {
                this.buffer = arg.nonce;
            } else {
                this.buffer = new Buffer(nacl.randomBytes(nacl.box.nonceLength));
            }
        } else {
            let b2 = blake2.createHash('blake2b', { digestLength: 24 });
            if (arg.nonce) {
                b2.update(arg.nonce.getBuffer());
            }

            b2.update(arg.clientKey);
            b2.update(arg.serverKey);

            this.buffer = b2.digest();
        }
    }

    increment() {
        let integer = this.buffer.readInt16LE(0);
        this.buffer.writeInt16LE(integer + 2, 0);
    }

    getBuffer() {
        return this.buffer;
    }
}

module.exports = Nonce;

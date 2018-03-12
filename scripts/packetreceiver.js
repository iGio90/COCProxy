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

class PacketReceiver {
    constructor() {
        this._buffer = null;
        this._packet = null;
    }

    packetize(data, callback) {
        let messageId, offset, payloadLength, ref, ref1, results;

        if (this._buffer) {
            this._buffer = Buffer.concat([this._buffer, data]);
        } else {
            this._buffer = data;
        }

        while (this._buffer && this._buffer.length) {
            if (this._packet && this._packet.length) {
                payloadLength = this._packet.readUIntBE(2, 3);

                if (this._buffer.length >= payloadLength) {
                    if (this._packet) {
                        this._packet = Buffer.concat([this._packet, this._buffer.slice(0, payloadLength)]);
                    } else {
                        this._packet = this._buffer.slice(0, payloadLength);
                    }

                    callback(this._packet);
                    this._packet = null;

                    this._buffer = this._buffer.slice(payloadLength);
                } else {
                    break;
                }
            } else if (this._buffer.length >= 7) {
                this._packet = this._buffer.slice(0, 7);
                this._buffer = this._buffer.slice(7);
            } else {
                // we'll be coming back here soon, but looks like we went through current buffer without a full header yet
                break;
            }
        }
    }
}

module.exports = PacketReceiver;

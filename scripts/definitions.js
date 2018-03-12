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

const fs = require('fs');
const zlib = require('zlib');

const Long = require("long");
const ByteBuffer = require("./bytebuffer-sc");
const EMsg = require('./emsg');

class Definitions {
    constructor() {
        let self = this;

        self.definitions = [];
        self.components = [];

        ['client', 'server', 'component'].forEach(function(folder) {
            let path = "cr-messages";
            fs.readdir('./node_modules/' + path + '/' + folder, (err, files) => {
                console.time('Loaded ' + folder + ' definitions in');
                if (err) {
                    return;
                }

                files.forEach(file => {
                    console.log('loading ' + folder +'/' + file +'...');

                    let json = JSON.parse(fs.readFileSync('./node_modules/' + path + '/' + folder + '/' + file, 'utf8'));

                    if (json.id) {
                        self.definitions[json.id] = json;
                    } else {
                        self.components[json.name] = json;

                        if (json.extensions) {
                            let extensions = [];

                            for (let key in json.extensions) {
                                extensions[json.extensions[key].id] = json.extensions[key];
                            }

                            self.components[json.name].extensions = extensions;
                        }
                    }
                });

                console.timeEnd('Loaded ' + folder + ' definitions in');
            });
        });
    }

    decode_fields(reader, fields) {
        let decoded = {};

        fields.forEach((field, index) => {
            let fieldType = field.type.substring(0); // creates a clone without reference

            if (!field.name) {
                field.name = "unknown_" + index;
            }

            if (fieldType.includes('?')) {
                if (Boolean(reader.readByte())) {
                    fieldType = fieldType.substring(1);
                } else {
                    reader.offset--; // we only peeked, multiple bools can be mixed together
                    decoded[field.name] = false;
                    return;
                }
            }

            // If the boolean before the type is false, use the left-hand side.
            // If the boolean before the type is true, use the right-hand side.
            if (fieldType.includes('||')) {
                if (Boolean(reader.readByte())) {
                    fieldType = fieldType.substring(fieldType.indexOf('||') + 2);
                } else {
                    fieldType = fieldType.substring(0, fieldType.indexOf('||'));
                }
            }
			
            if (fieldType.includes('[')) {
                let n = fieldType.substring(fieldType.indexOf('[') + 1, fieldType.indexOf(']'));
                fieldType = fieldType.substring(0, fieldType.indexOf('['));

                // if n is specified, then we use it, otherwise we need to read how big the array is
                // may need to implement lenghtType, but seems unecessary, they are all RRSINT32 afaik
                if (n === '') {
                    if(field.lengthType && field.lengthType === 'INT') {
                        n = reader.readInt32();
                    } else {
                        n = reader.readRrsInt32();
                    }
                } else {
                    n = parseInt(n);
                }

                decoded[field.name] = [];

                for (let i = 0; i < n; i++) {
                    decoded[field.name][i] = this.decode_field(reader, fieldType, field);
                }
            } else {
                decoded[field.name] = this.decode_field(reader, fieldType, field);
            }
        });

        return decoded;
    }

    decode_field(reader, fieldType, field) {
		reader.BE(); //Always use Big Endian
		
        let decoded;

        if (fieldType === 'BYTE') {
            decoded = reader.readByte();
        } else if (fieldType === 'SHORT') {
            decoded = reader.readInt16();
        } else if (fieldType === 'BOOLEAN'){
            decoded = Boolean(reader.readByte());
        } else if (fieldType === 'INT') {
            decoded = reader.readInt32();
        } else if (fieldType === 'INT32') {
            decoded = reader.readVarint32();
        } else if (fieldType === 'RRSINT32') {
            decoded = reader.readRrsInt32();
        } else if (fieldType === 'RRSLONG') {
            decoded = Long.fromValue({high: reader.readRrsInt32(), low: reader.readRrsInt32(), unsigned: false});
        } else if (fieldType === 'LONG') {
            decoded = reader.readInt64();
        } else if (fieldType === 'STRING') {
            decoded = reader.readIString();
        } else if (fieldType === 'BITSET') {
            let bits = reader.readByte();

            decoded = [
                !!(bits & 0x01),
                !!(bits & 0x02),
                !!(bits & 0x04),
                !!(bits & 0x08),
                !!(bits & 0x10),
                !!(bits & 0x20),
                !!(bits & 0x40),
                !!(bits & 0x80)
            ];

            if(field.bit) {
                decoded = decoded[field.bit];
            }

            if(field.peek === true) {
                reader.offset--;
            }
        } else if (fieldType === 'SCID') {
            let hi = reader.readRrsInt32();
            let lo;
            if(hi) {
                lo = reader.readRrsInt32();
                decoded = hi * 1000000 + lo;
            } else {
                decoded = 0;
            }
        } else if (fieldType === 'SCSV') {
            let id = reader.readInt32();
            let value = reader.readInt32();
			
            decoded = {id: id, value: value};
        } else if (fieldType === 'TIMESTAMP') {
            let timestamp = reader.readInt32();

            let d = new Date(0);
            d.setUTCSeconds(timestamp);

            decoded = {timestamp: timestamp, date: d.toDateString()};
        } else if (fieldType === 'ZIP_STRING') {
			let compressedLen = reader.readInt32() - 4;
			
			reader.LE(); //Zlib uses Little Endian
			
			let decompressedLen = reader.readInt32();
			
            if(reader.remaining() >= compressedLen) {
                decoded =  {compressed: compressedLen,
                            decompressed: decompressedLen,
                            data: zlib.unzipSync(reader.slice(reader.offset, reader.offset + compressedLen).toBuffer()).toString()};
                reader.offset = reader.offset + compressedLen;
            } else {
                decoded = false;
                console.log('Insufficient data to unzip field.');
            }
        } else if (fieldType === 'IGNORE') {
            decoded = reader.remaining() + ' bytes have been ignored.';
            reader.offset = reader.limit;
        } else if (this.components[fieldType]) {
            decoded = this.decode_fields(reader, this.components[fieldType].fields);
            if (this.components[fieldType].extensions !== undefined) {

                if (decoded.id !== undefined) {
                    let extensionDef = this.components[fieldType].extensions.find(function(extension) {
                        if (extension) {
                            return extension.id === decoded.id;
                        } else {
                            return 0;
                        }
                    });

                    if (extensionDef) {
                        decoded.name = extensionDef.name;
                        decoded.payload = this.decode_fields(reader, extensionDef.fields);
                    } else {
                        console.warn('Error: Extensions of field type ' + fieldType + ' with id ' + decoded.id + ' is missing. (' + field.name + ').');
                        return false;
                    }
                } else {
                    console.warn('Warning: missing id for component ' + fieldType + ' (' + field.name + ').');
                    return false;
                }
            }
        } else {
            console.error('Error: field type ' + fieldType + ' does not exist. (' + field.name + '). Exiting.');
            process.exit(1);
        }

        return decoded;
    }

    decode(message) {
        let reader = ByteBuffer.fromBinary(message.decrypted);

        if (this.definitions[message.messageType]) {
            message.decoded = {};

            if (this.definitions[message.messageType].fields && this.definitions[message.messageType].fields.length) {
                message.decoded = this.decode_fields(reader, this.definitions[message.messageType].fields);
            }

            if (reader.remaining()) {
                console.log(reader.remaining() + ' bytes remaining...');
                reader.printDebug();
            }
        } else {
            console.log('Missing definition for ' + (EMsg[message.messageType] ? EMsg[message.messageType] : message.messageType));
            reader.printDebug();
        }
    }
}

module.exports = Definitions;

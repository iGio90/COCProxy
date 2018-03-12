'use strict';

var net = require('net');
var fs = require('fs');
var util = require('util');
var path = require('path');
var jsome = require('jsome');

require('console-stamp')(console, 'yyyy-mm-dd HH:MM:ss');

var ByteBufferSc = require('./scripts/bytebuffer-sc')
var PacketReceiver = require('./scripts/packetreceiver');
var ClientCrypto = require('./scripts/client_crypto');
var ServerCrypto = require('./scripts/server_crypto');
var Definitions = require('./scripts/definitions');
var EMsg = require('./scripts/emsg');

var definitions = new Definitions();
var clients = {};

var server = net.createServer();

server.on('error', function(err) {
    if (err.code == 'EADDRINUSE') {
        console.log('Address in use, exiting...');
    } else {
        console.log('Unknown error setting up proxy: ' + err);
    }

    process.exit(1);
});

server.on('listening', function() {
    console.log('listening on ' + server.address().address + ':' + server.address().port);
});

server.on('connection', function(socket) {
    var gameserver = new net.Socket();
    socket.key = socket.remoteAddress + ":" + socket.remotePort;
    clients[socket.key] = socket;

    var clientPacketReceiver = new PacketReceiver();
    var serverPacketReceiver = new PacketReceiver();

    var clientCrypto = new ClientCrypto();
    var serverCrypto = new ServerCrypto();

    clientCrypto.setServerCrypto(serverCrypto);
    serverCrypto.setClientCrypto(clientCrypto);

    clientCrypto.setPublicServerKey(Buffer.from('D6485BE4214701F45259CB4124F7A8261E0BF1A54BA7C066CD50F7AE9289D936', 'hex'))
    serverCrypto.setPublicServerKey(Buffer.from('D6485BE4214701F45259CB4124F7A8261E0BF1A54BA7C066CD50F7AE9289D936', 'hex'))

    console.log('new client ' + socket.key + ' connected, establishing connection to game server');

    gameserver.connect(9339, "gamea.clashofclans.com", function() {
        console.log('Connected to game server on ' + gameserver.remoteAddress + ':' + gameserver.remotePort);
    });

    gameserver.on("data", function(chunk) {
        serverPacketReceiver.packetize(chunk, function(packet) {
            var message = {
                'messageType': packet.readUInt16BE(0),
                'length': packet.readUIntBE(2, 3),
                'version': packet.readUInt16BE(5),
                'payload': packet.slice(7, packet.length)
            };

            console.log('[SERVER] ' + (EMsg[message.messageType] ? EMsg[message.messageType] + ' [' + message.messageType + ']' : message.messageType));

            serverCrypto.decrypt(message);
            definitions.decode(message);
            if (message.decoded) {
                jsome(message.decoded);
            }

            serverCrypto.encrypt(message);

            var header = Buffer.alloc(7);

            header.writeUInt16BE(message.messageType, 0);
            header.writeUIntBE(message.encrypted.length, 2, 3);
            header.writeUInt16BE(message.version, 5);

            clients[socket.key].write(Buffer.concat([header, Buffer.from(message.encrypted)]));
        });
    });

    gameserver.on("end", function() {
        console.log('Disconnected from game server');
    });

    clients[socket.key].on('data', function(chunk) {
        clientPacketReceiver.packetize(chunk, function(packet) {
            var message = {
                'messageType': packet.readUInt16BE(0),
                'length': packet.readUIntBE(2, 3),
                'version': packet.readUInt16BE(5),
                'payload': packet.slice(7, packet.length)
            };

            console.log('[CLIENT] ' + (EMsg[message.messageType] ? EMsg[message.messageType] + ' [' + message.messageType + ']' : message.messageType));

            clientCrypto.decrypt(message);
            definitions.decode(message);
            if (message.decoded) {
                jsome(message.decoded);
            }
            clientCrypto.encrypt(message);

            let header = Buffer.alloc(7);

            header.writeUInt16BE(message.messageType, 0);
            header.writeUIntBE(message.encrypted.length, 2, 3);
            header.writeUInt16BE(message.version, 5);

            gameserver.write(Buffer.concat([header, Buffer.from(message.encrypted)]));
        });
    });

    clients[socket.key].on('end', function() {
        console.log('Client ' + socket.key + ' disconnected from proxy.');
        delete clients[socket.key];
        gameserver.end();
    });
});

server.listen({ host: '0.0.0.0', port: 9339, exclusive: true }, function(err) {
    if (err) {
        console.log(err);
    }
});
//
// -- Zetta Toolkit - JSON RPC over TLS
//
//  Copyright (c) 2011-2014 ASPECTRON Inc.
//  All Rights Reserved.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
// 
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
// 
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

var _ = require("underscore");
var fs = require("fs");
var net = require("net");
var tls = require('tls');
var crypto = require('crypto');
var colors = require('colors');
var events = require('events');
var util = require('util');

if(!GLOBAL.dpc)
    GLOBAL.dpc = function(t,fn) { if(typeof(t) == 'function') setTimeout(t,0); else setTimeout(fn,t); }

var zetta_rpc_default_verbose = true;
var zetta_rpc_default_cipher = false;

function encrypt(text, cipher, key){
    var cipher = crypto.createCipher(cipher, key)
    var crypted = cipher.update(text, 'utf8', 'hex')
    crypted += cipher.final('hex');
    return crypted;
}
 
function decrypt(text, cipher, key){
    var decipher = crypto.createDecipher(cipher, key)
    var dec = decipher.update(text,'hex', 'utf8')
    dec += decipher.final('utf8');
    return dec;
}

function Client(options) {
    var self = this;
    events.EventEmitter.call(this);

    if(!options.node)
        throw new Error("zetta-rpc::Client requires node argument containing node id");
    if(!options.designation)
        throw new Error("zetta-rpc::Client requires designation argument");
    if(!options.certificates)
        throw new Error("zetta-rpc::Client requires certificates argument");
    if(!options.address)
        throw new Error("zetta-rpc::Client requires address argument");
    if(!options.auth)
        throw new Error("zetta-rpc::Client requires key argument");

    self.listeners = [ self ]
    self.connected = false;
    self.buffer = '';
    self.address = options.address.split(':');
    self.infoObject = { }
    self.pingFreq = options.pingFreq || 3 * 1000;
    self.sequence = 0;
    self.verbose = options.verbose || zetta_rpc_default_verbose;
    self.pk = crypto.createHash('sha512').update(options.auth).digest('hex');
    self.signatures = options.signatures || true;
    self.cipher = options.cipher || zetta_rpc_default_cipher;
    if(self.cipher === true)
        self.cipher = 'aes-256-cbc';

    if(self.verbose)
        console.log("zetta-rpc connecting to address:", self.address);

    var tlsOptions = { }
    tlsOptions.host = self.address[0];
    tlsOptions.port = parseInt(self.address[1]);
    tlsOptions.rejectUnauthorized = false;
    _.extend(tlsOptions, options.certificates);

    function connect() {
        self.auth = false;
        self.stream = tls.connect(8000, tlsOptions, function () {
            console.log('zetta-rpc connected to server, SSL certificate is', self.stream.authorized ? 'authorized' : 'unauthorized');

            if (self.connected)
                console.error("zetta-rpc ERROR - INVALID TLS RECONNECTION ATTEMPT!".magenta.bold);

            self.stream.write(JSON.stringify({ op : 'auth-request'}) + '\n');
            self.connected = true;
        });
        self.stream.setEncoding('utf8');
        self.stream.on('data', function (data) {

            if (self.buffer.length + data.length > 1024 * 65) {
                self.buffer = data;
                // return;
            }

            self.buffer += data;

            var idx = self.buffer.indexOf('\n');
            if (~idx) {
                var msg = self.buffer.substring(0, idx);
                self.buffer = self.buffer.substring(idx + 1);
                try {

                    if(self.auth && self.cipher)
                        msg = decrypt(msg, self.cipher, self.pk);

                    digest(JSON.parse(msg));
                }
                catch (ex) {
                    console.log(ex.stack);
                    self.stream.end();
                }
            }

        });
        self.stream.on('error', function (err) {
            if(self.verbose && self.connected)
                console.log("zetta-rpc tls stream error:", err.message);

            if(self.connected)
                emit('disconnect', self.stream);

            self.connected = false;
            self.auth = false;
            dpc(1000, connect);
        });
        self.stream.on('end', function () {
            if(self.verbose)
                console.log("zetta-rpc tls stream closed");
            self.connected = false;
            self.auth = false;
            dpc(1000, connect);
            emit('disconnect', self.stream);
        });
    }

    function digest(msg) {

        if(msg.op == 'auth') {
            var vector = msg.vector;
            if(!vector) {
                console.log("zetta-rpc: no vector in auth message");
                self.stream.end();
                return;
            }

            var auth = crypto.createHmac('sha256', self.pk).update(vector).digest('hex');
            self.auth = true;

            var msg = {
                op : 'auth',
                cipher : self.cipher ? encrypt(self.cipher, 'aes-256-cbc', self.pk) : false,
            }

            var data = { 
                op : 'auth', 
                auth : auth, 
                signatures : self.signatures, 
                node : options.node, 
                designation : options.designation 
            }

            msg.data = self.cipher ? encrypt(JSON.stringify(data), 'aes-256-cbc', self.pk) : data;

            writeJSON(msg);

            if(self.signatures) {
                var seq_auth = crypto.createHmac('sha1', self.pk).update(vector).digest('hex');
                self.sequenceTX = parseInt(seq_auth.substring(0, 8), 16);
                self.sequenceRX = parseInt(seq_auth.substring(8, 16), 16);
            }

            return;
        }

        if(self.signatures) {
            var sig = crypto.createHmac('sha256', self.pk).update(self.sequenceRX+'').digest('hex').substring(0, 16);
            if(msg._sig != sig) {
                console.log("zetta-rpc signature failure:", msg);
                self.stream.end();
                return;
            }
            self.sequenceRX++;
            delete msg._sig;
        }

        msg.op && emit(msg.op, msg, self);
        self.digestCallback && self.digestCallback(msg, self);
    }

    function emit() {
        var args = arguments;
        _.each(self.listeners, function(listener) {
            try {
                listener.emit.apply(listener, arguments);
            } catch(ex) {
                console.error("zetta-rpc: error while processing message".magenta.bold);
                console.error(ex.stack);
            }
        })
    }

    self.digest = function(callback) {
        self.digestCallback = callback;
    }

    self.registerListener = function(listener) {
        self.listeners.push(listener);
    }

    function writeJSON(msg) {
        if (!self.connected || !self.auth)
            return false;
        self.stream.write(JSON.stringify(msg) + '\n');
        return true;
    }

    self.dispatch = function (_msg, callback) {
        if (!self.connected || !self.auth)
            return false;

        var msg = _msg;

        if(self.signatures) {
            msg = _.clone(_msg);
            msg._sig = crypto.createHmac('sha256', self.pk).update(self.sequenceTX+'').digest('hex').substring(0, 16);
            self.sequenceTX++;
        }

        var text = JSON.stringify(msg);
        if(self.cipher)
            text = encrypt(text, self.cipher, self.pk);
        self.stream.write(text + '\n', callback);
        return true;
    }

    self.setPingDataObject = function(o) {
        self.pingDataObject = o;
    }

    function ping() {
        self.dispatch({ op : 'ping', data : self.pingDataObject});
        dpc(self.pingFreq, ping);
    }

    dpc(connect);

    if(options.ping || options.pingFreq) {
        dpc(function () {
            ping();
        })
    }
}

util.inherits(Client, events.EventEmitter);


function Multiplexer(options) {
    var self = this;
    events.EventEmitter.call(this);
    self.servers = { }

    if(_.isArray(options.address)) {
        _.each(options.address, function (address) {
            var clientOptions = { }
            _.extend(clientOptions, options);
            clientOptions.address = address;
            console.log("init rpc @" + clientOptions.address.bold);
            self.servers[clientOptions.address] = new Client(clientOptions);
            self.servers[clientOptions.address].registerListener(self);
        })
    }
    else {
        console.log("init rpc @" + options.address.bold);
        self.servers[options.address] = new Client(options);
    }


    self.dispatch = function (msg) {
        _.each(self.servers, function (server) {
            server.dispatch(msg);
        })
    }

    self.setPingDataObject = function(o) {
        _.each(self.servers, function (server) {
            server.setPingDataObject(o);
        })
    }

    self.digest = function(callback) {
        _.each(self.servers, function (server) {
            server.digest(callback);
        })
    }

    self.registerListener = function(listener) {
        _.each(self.servers, function (server) {
            server.registerListener(listener);
        })
    }
}

util.inherits(Multiplexer, events.EventEmitter);

function Server(options, init_callback) { // port, certificates) {
	var self = this;
    events.EventEmitter.call(this);

	self.streams = { };
	self.connectionCount = 0;
    self.verbose = options.verbose || zetta_rpc_default_verbose;
    self.pk = crypto.createHash('sha512').update(options.auth).digest('hex');

    self.server = tls.createServer(options.certificates, function (stream) {
        var buffer = '';
        stream.setEncoding('utf8');
        stream.on('data', function (data) {
            if (buffer.length + data.length > 1024 * 65) {
                buffer = data;
            }

            buffer += data;

            var idx = buffer.indexOf('\n');
            if (~idx) {
                var msg = buffer.substring(0, idx);
                buffer = buffer.substring(idx + 1);
                try {
                    if(stream.__cipher__)
                        msg = decrypt(msg, stream.__cipher__, self.pk);
                    digest(JSON.parse(msg), stream);
                }
                catch (ex) {
                    console.log(ex.stack);
                    stream.end();
                }
            }

        });
        stream.on('error', function (err) {
            //if(self.verbose)
            //    console.log("zetta-rpc tls stream error:", err.message);
            stream.end();
            disconnect(stream);
        });
        stream.on('end', function () {
            //if(self.verbose)
            //    console.log("zetta-rpc tls stream error:", err.message);
            disconnect(stream);
        });
    });

    self.server.listen(options.port, function(err) {
        if(err)
            console.error('zetta-rpc server listen error on '+options.port, err);
        init_callback && init_callback(err);
    });

    function digest(msg, stream) {

        if(msg.op == 'auth-request') {
            var vector = crypto.createHash('sha512').update(crypto.randomBytes(512)).digest('hex');
            stream.__vector__ = vector;
            stream.write(JSON.stringify({ op : 'auth', vector : vector })+'\n');
            return;
        }

        if(msg.op == 'auth') {
            try {

                var data = msg.data;
                if(!data) {
                    console.log("zetta-rpc auth packet missing data:", msg);
                    stream.end();
                    return;
                }

                if(msg.cipher) {
                    stream.__cipher__ = decrypt(msg.cipher, 'aes-256-cbc', self.pk);
                    data = JSON.parse(decrypt(data, stream.__cipher__, self.pk));
                }

                if(!data.node || !data.designation || !data.auth) {
                    console.log("zetta-rpc auth packet missing auth, node or designation:", msg);
                    stream.end();
                    return;
                }

                var auth = crypto.createHmac('sha256', self.pk).update(stream.__vector__).digest('hex');
                if(auth != data.auth) {
                    console.log("zetta-rpc auth failure:", data);
                    stream.end();
                    return;
                }

                stream.__node__ = data.node;
                stream.__designation__ = data.designation;
                stream.__client_id__ = data.designation+'-'+data.node;
                stream.__signatures__ = data.signatures;

                if(stream.__signatures__) {
                    var sig_auth = crypto.createHmac('sha1', self.pk).update(stream.__vector__).digest('hex');
                    stream.__sequenceRX__ = parseInt(sig_auth.substring(0, 8), 16);
                    stream.__sequenceTX__ = parseInt(sig_auth.substring(8, 16), 16);
                }

            }
            catch(ex) {
                console.log("generic failure during auth:", ex.stack);
                stream.end();
                return;
            }

            self.streams[stream.__client_id__] = stream;

            self.connectionCount++;
            self.emit('connect', stream.servername, stream.__client_id__, stream.__designation__, stream.__node__, stream);

            return;
        }

        if(!stream.__client_id__) {
            console.log("zetta-rpc foreign connection, closing");
            stream.end();
            return;
        }

        if(stream.__signatures__) {
            var sig = crypto.createHmac('sha256', self.pk).update(stream.__sequenceRX__+'').digest('hex').substring(0, 16);
            if(msg._sig != sig) {
                console.log("zetta-rpc signature failure:", msg);
                stream.end();
                return;
            }
            stream.__sequenceRX__++;
            delete msg._sig;
        }

        try {
            self.digestCallback && self.digestCallback(msg, stream.__client_id__, stream.__designation__, stream.__node__, stream);
            msg.op && self.emit(msg.op, msg, stream.__client_id__, stream.__designation__, stream.__node__, stream);
        } catch(ex) {
            console.error("zetta-rpc: error while processing message".magenta.bold);
            console.error(ex.stack);
        }
    }

    function disconnect(stream) {
        self.connectionCount--;
        delete self.streams[stream.__client_id__];
        self.emit('disconnect', stream.__client_id__, stream);
    }

    self.dispatch = function (cid, _msg, callback) {
        var stream = self.streams[cid];
        if(!stream) {
            console.error('zetta-rpc: no such stream present:'.magenta.bold,cid);
            return false;
        }

        var msg = _msg;

        if(stream.__signatures__) {
            msg = _.clone(_msg);
            msg._sig = crypto.createHmac('sha256', self.pk).update(stream.__sequenceTX__+'').digest('hex').substring(0, 16);
            stream.__sequenceTX__++;
        }

        var text = JSON.stringify(msg);
        if(stream.__cipher__)
            text = encrypt(text, stream.__cipher__, self.pk);
        stream.write(text + '\n', callback);
        return true;
    }

    self.digest = function(callback) {
        self.digestCallback = callback;
    }

}

util.inherits(Server, events.EventEmitter);

module.exports = {
	Client : Client,
	Multiplexer : Multiplexer,
	Server : Server
}
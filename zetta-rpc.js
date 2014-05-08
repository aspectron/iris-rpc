//
// -- Zetta Toolkit - JSON Interface over TLS
//
//  Copyright (c) 2014 ASPECTRON Inc.
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
var UUID = require('node-uuid');

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


function Stream(tlsStream, iface) {
	var self = this;
	self.tlsStream = tlsStream;
	self.buffer = '';

    if(iface.rejectUnauthorized && !tlsStream.authorized)
        return tlsStream.end();

    iface.connectionCount++;

    tlsStream.setEncoding('utf8');

    tlsStream.on('data', function (data) {
        if (self.buffer.length + data.length > 1024 * 65) {
            self.buffer = data;
        }

        self.buffer += data;

        var idx = self.buffer.indexOf('\n');
        if (~idx) {
            var msg = self.buffer.substring(0, idx);
            self.buffer = self.buffer.substring(idx + 1);
            try {
                if(self.cipher)
                    msg = decrypt(msg, self.cipher, iface.pk);

                console.log(msg);
                
                iface.emit('stream::message',JSON.parse(msg), self);
            }
            catch (ex) {
                console.log(ex.stack);
                tlsStream.end();
            }
        }

    });
    tlsStream.on('error', function (err) {
    	iface.connectionCount--;
        if(iface.verbose)
            console.log("zetta-rpc tls stream error:", err.message);
    	iface.emit('stream::error', err, self);
    	//self.removeAllListeners();
        //stream.end();
        //disconnect(stream);
    });
    tlsStream.on('end', function () {
    	iface.connectionCount--;
//        if(iface.verbose)
//            console.log("zetta-rpc tls stream end");
        //disconnect(stream);
        iface.emit('stream::end', self)
    	//self.removeAllListeners();
    });


    self.end = function() {
    	iface.connectionCount--;
    	tlsStream.end();
        iface.emit('stream::end', self)
    }

    self.writeJSON = function(msg) {
        self.tlsStream.write(JSON.stringify(msg) + '\n');
        return true;
    }

    self.writeTEXT = function(text, callback) {
        self.tlsStream.write(text + '\n', callback);
        return true;
    }

}

function Interface(options) {
	var self = this;
    events.EventEmitter.call(this);
//console.log(self);
//    if(!options.node)
//        throw new Error("zetta-rpc::Client requires node argument containing node id");
//    if(!options.designation)
//        throw new Error("zetta-rpc::Client requires designation argument");
    if(!options.certificates)
        throw new Error("zetta-rpc::Client requires certificates argument");
    if(!options.auth && !options.secret)
        throw new Error("zetta-rpc::Client requires auth argument");

	self.listeners = [ self ]
	self.streams = { }
    self.infoObject = { }
    self.pingFreq = options.pingFreq || 3 * 1000;
    self.pingDataObject = options.pingDataObject;
    self.verbose = options.verbose || zetta_rpc_default_verbose;
    self.pk = crypto.createHash('sha512').update(options.auth || options.secret).digest('hex');
    self.rejectUnauthorized = options.rejectUnauthorized || false;
    self.signatures = options.signatures || true;
    self.cipher = options.cipher || false;
    if(self.cipher === true)
        self.cipher = 'aes-256-cbc';
    self.routes = options.routes || null;


    self.iface = { }


    self.iface['rpc::auth::request'] = function(msg, stream) {
        var vector = crypto.createHash('sha512').update(crypto.randomBytes(512)).digest('hex');
        stream.vector = vector;
        stream.writeJSON({ op : 'rpc::auth::challenge', vector : vector });
    }

    self.iface['rpc::auth::challenge'] = function(msg, stream) {

        var vector = msg.vector;
        if(!vector) {
            console.log("zetta-rpc: no vector in auth message");
            stream.end();
            return;
        }

        var auth = crypto.createHmac('sha256', self.pk).update(vector).digest('hex');
//	            stream.auth = true;

        var msg = {
            op : 'rpc::auth::response',
            cipher : self.cipher ? encrypt(self.cipher, 'aes-256-cbc', self.pk) : false,
        }

        var data = { 
            // op : 'auth', 
            auth : auth, 
            signatures : self.signatures, 
            node : options.node || UUID.v1(), 
            designation : options.designation || ''
        }

        msg.data = self.cipher ? encrypt(JSON.stringify(data), 'aes-256-cbc', self.pk) : data;

        stream.writeJSON(msg);

        if(self.signatures) {
            var seq_auth = crypto.createHmac('sha1', self.pk).update(vector).digest('hex');
            self.sequenceTX = parseInt(seq_auth.substring(0, 8), 16);
            self.sequenceRX = parseInt(seq_auth.substring(8, 16), 16);
        }

        if(self.cipher)
        	stream.cipher = self.cipher;

        stream.auth = true;
    }

    self.iface['rpc::auth::response'] = function(msg, stream) {
        try {

            var data = msg.data;
            if(!data) {
                console.log("zetta-rpc auth packet missing data:", msg);
                stream.end();
                return;
            }

            if(msg.cipher) {
                stream.cipher = decrypt(msg.cipher, 'aes-256-cbc', self.pk);
                data = JSON.parse(decrypt(data, stream.__cipher__, self.pk));
            }

            if(!data.node || !data.designation || !data.auth) {
                console.log("zetta-rpc auth packet missing auth, node or designation:", msg);
                stream.end();
                return;
            }

            var auth = crypto.createHmac('sha256', self.pk).update(stream.vector).digest('hex');
            if(auth != data.auth) {
                console.log("zetta-rpc auth failure:", data);
                stream.end();
                return;
            }

            stream.node = data.node;
            stream.designation = data.designation;
            stream.cid = data.designation ? data.designation+'-'+data.node : data.node;
            stream.signature = data.signatures;

            if(stream.signatures) {
                var sig_auth = crypto.createHmac('sha1', self.pk).update(stream.vector).digest('hex');
                stream.sequenceRX = parseInt(sig_auth.substring(0, 8), 16);
                stream.sequenceTX = parseInt(sig_auth.substring(8, 16), 16);
            }

        }
        catch(ex) {
            console.log("generic failure during auth:", ex.stack);
            stream.end();
            return;
        }

        self.streams[stream.cid] = stream;

        // SEND ROUTING INFO

        self.dispatch(stream.cid, { 
        	op : 'rpc::init', 
        	data : {
        		node : options.node || UUID.v1(),
        		designation : options.designation || ''
        	},
        	routes : _.keys(self.routes)
        })
    }

    self.iface['rpc::init'] = function(msg, stream) {

		var data = msg.data;
		if(data) {
			self.dispatch({ op : 'rpc::init', routes : _.keys(self.routes) })

			stream.node = data.node;
			stream.designation = data.designation;
            stream.cid = data.designation ? data.designation+'-'+data.node : data.node;
            self.streams[stream.cid] = stream;
//	                stream.signature = data.signatures;
		}

		self.routes = { }
		_.each(msg.routes, function(route) {
			self.routes[route] = stream;
		})

		stream.connected = true;
        self.emitToListeners('connect', stream.servername, stream.cid, stream);

    }


	self.on('stream::message', function(msg, stream) {

        if(msg._sig) { //stream.signatures) {
            var sig = crypto.createHmac('sha256', self.pk).update(stream.sequenceRX+'').digest('hex').substring(0, 16);
            if(msg._sig != sig) {
                console.log("zetta-rpc signature failure:", msg);
                stream.end();
                return;
            }
            stream.sequenceRX++;
            delete msg._sig;
        }

        if(self.iface[msg.op]) {
        	self.iface[msg.op].call(self, msg, stream);
        	return;
        }
        else
        if(!stream.cid) {
            console.log("zetta-rpc foreign connection "+stream.address+", closing");
            stream.end();
            return;
        }


        try {
            
            var cid = msg._r ? msg._r.cid : stream.cid;
            //var designation = msg._r ? msg._r.designation : stream.designation;
            //var node = msg._r ? msg._r.node : stream.node;

            self.digestCallback && self.digestCallback(msg, cid, stream);
            msg.op && self.emitToListeners(msg.op, msg, cid, stream);

        } catch(ex) {
            console.error("zetta-rpc: error while processing message".magenta.bold);
            console.error(ex.stack);
        }

	})

	self.on('stream::error', function(err, stream) {
		console.log("deleting stream".cyan.bold, stream.cid);
		delete self.streams[stream.cid];
	})

	self.on('stream::end', function(stream) {
		console.log("deleting stream".cyan.bold, stream.cid);
		delete self.streams[stream.cid];
	})



    self.emitToListeners = function() {
        var args = arguments;
        _.each(self.listeners, function(listener) {
            try {
                listener.emit.apply(listener, args);
            } catch(ex) {
                console.error("zetta-rpc: error while processing message".magenta.bold);
                console.error(ex.stack);
            }
        })
    }

//-----

	self.dispatchToStream = function(stream, _msg, callback) {

        var msg = _.clone(_msg);
        if(self.routing)
            msg._cid = cid;

        if(stream.signatures) {
            msg._sig = crypto.createHmac('sha256', self.pk).update(stream.sequenceTX+'').digest('hex').substring(0, 16);
            stream.sequenceTX++;
        }

        var text = JSON.stringify(msg);
        if(stream.__cipher__)
            text = encrypt(text, stream.cipher, self.pk);
        stream.writeTEXT(text, callback);

        return true;
	}

    self.dispatch = function (cid, msg, callback) {

    	if(_.isObject(cid)) {
    		msg = cid;
    		callback = msg;
    		cid = null;

	    	_.each(self.streams, function(stream) {
	    		self.dispatchToStream(stream, msg);
	    	})
    	}
    	else {
    		var stream = self.streams[cid];
    		if(!stream) {
	            console.error('zetta-rpc: no such stream present:'.magenta.bold, cid);
	            callback && callback(new Error("zetta-rpc: no such stream present"))
	            return;
    		}

    		self.dispatchToStream(stream, msg, callback);
    	}
    }

    self.digest = function(callback) {
        self.digestCallback = callback;
    }

    self.registerListener = function(listener) {
    	self.listeners.push(listener);
    }

}

util.inherits(Interface, events.EventEmitter);


function Client(options) {
	var self = this;
	Interface.call(this, options);

    if(!options.address)
        throw new Error("zetta-rpc::Client requires address argument");

	if(_.isArray(options.address)) {
		_.each(options.address, function(address) {
			createConnection(address);
		})
	}
	else
		createConnection(options.address);


	function createConnection(address) {

	    var addr = address.split(':');

	    if(self.verbose)
	        console.log("zetta-rpc connecting to address:", address);

	    var tlsOptions = { }
	    tlsOptions.host = addr[0];
	    tlsOptions.port = parseInt(addr[1]);
	    tlsOptions.rejectUnauthorized = options.rejectUnauthorized || false;
	    _.extend(tlsOptions, options.certificates);

        self.auth = false;
        var tlsStream = tls.connect(tlsOptions, function () {
            console.log('zetta-rpc connected to server, SSL certificate is', tlsStream.authorized ? 'authorized' : 'unauthorized');
            if(self.rejectUnauthorized && !tlsStream.authorized)
                return tlsStream.end();

            stream.writeJSON({ op : 'rpc::auth::request'});
        });

        var stream = new Stream(tlsStream, self);
        stream.address = address;
	}

    self.on('stream::error', function(err, stream) {
        self.emitToListeners('disconnect', stream);
        //delete self.clientStream;
        dpc(1000, function() {
        	createConnection(stream.address);
        });
    })

    self.on('stream::end', function(stream) {
        self.emitToListeners('disconnect', stream);
        //delete self.clientStream;
        dpc(1000, function() {
        	createConnection(stream.address);
        });
    })

    self.isConnected = function() {
//    	console.log("self.streams".yellow.bold, self.streams);
 		for(var i in self.streams) { return true; } return false;
    }
}

util.inherits(Client, Interface);



function Server(options, initCallback) {
	var self = this;
	Interface.call(this, options);

    if(!options.port)
        throw new Error("zetta-rpc::Server requires port argument");


    self.tlsServer = tls.createServer(options.certificates, function (tlsStream) {
        if(self.rejectUnauthorized && !stream.authorized)
            return stream.end();
        var stream = new Stream(tlsStream, self);
    });

    self.tlsServer.listen(options.port, function(err) {
        if(err)
            console.error('zetta-rpc server listen error on '+options.port, err);
        self.emitToListeners('server::listen', err);
        initCallback && initCallback(err);
    });



    self.on('stream::error', function(err, stream) {
        self.emitToListeners('disconnect', stream);
        stream.tlsStream.end();

    })

    self.on('stream::end', function(stream) {
        self.emitToListeners('disconnect', stream);
    })

}

util.inherits(Server, Interface);




module.exports = {
	Client : Client,
//	Multiplexer : Multiplexer,
	Server : Server
}

/*
var c = new Client();
console.log(c);
console.log(c.prototype);
console.log(c.abc);


c.on('abc', function() {
	console.log('got abc msg');
})

c.emit('abc');

console.log('instance of Peer:', c instanceof Peer);

console.log('instance of EventEmitter:', c instanceof events.EventEmitter);


*/
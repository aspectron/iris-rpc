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

var config = {
    verbose : false,
    cipher : true,
    debug : false
}

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


function Stream(tlsStream, iface, address) {
	var self = this;
	self.tlsStream = tlsStream;
	self.buffer = '';
    self.address = tlsStream.socket.remoteAddress || address;
    self.serverName = tlsStream.servername;


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
        if(config.verbose)
            console.log("zetta-rpc tls stream error:", err.message);
    	iface.emit('stream::error', err, self);
    });

    tlsStream.on('end', function () {
    	iface.connectionCount--;
        if(config.verbose)
            console.log("zetta-rpc tls stream end");
        iface.emit('stream::end', self)
    });

    self.end = function() {
    	iface.connectionCount--;
    	tlsStream.end();
    }

    self.writeJSON = function(msg) {
        if(config.debug)
            console.log('<--'.bold,msg);
        self.tlsStream.write(JSON.stringify(msg) + '\n');
        return true;
    }

    self.writeTEXT = function(text, callback) {
        // console.log(text);
        //if(config.debug)
        //    console.log('<--',text);
        self.tlsStream.write(text + '\n', callback);
        return true;
    }

}

function Interface(options) {
	var self = this;
    events.EventEmitter.call(this);

    if(!options.certificates)
        throw new Error("zetta-rpc::Client requires certificates argument");
    if(!options.auth && !options.secret)
        throw new Error("zetta-rpc::Client requires auth argument");

	self.listeners = [ self ]
	self.streams = { }
    self.pingFreq = options.pingFreq || 3 * 1000;
    self.pingDataObject = options.pingDataObject;
    self.pk = crypto.createHash('sha512').update(options.auth || options.secret).digest('hex');
    self.rejectUnauthorized = options.rejectUnauthorized || false;
    self.signatures = options.signatures || true;
    self.cipher = options.cipher || config.cipher;
    if(self.cipher === true)
        self.cipher = 'aes-256-cbc';
    self.routes = {
        local : options.routes || null,
        remote : { }
    }

    self.iface = { }

    // Server
    self.iface['rpc::auth::request'] = function(msg, stream) {  
        var vector = crypto.createHash('sha512').update(crypto.randomBytes(512)).digest('hex');
        stream.vector = vector;
        stream.writeJSON({ op : 'rpc::auth::challenge', vector : vector });
    }

    // Client
    self.iface['rpc::auth::challenge'] = function(msg, stream) {

        var vector = msg.vector;
        if(!vector) {
            console.log("zetta-rpc: no vector in auth message");
            stream.end();
            return;
        }

        var auth = crypto.createHmac('sha256', self.pk).update(vector).digest('hex');

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

        stream.signatures = self.signatures;
        var seq_auth = crypto.createHmac('sha1', self.pk).update(vector).digest('hex');
        stream.sequenceTX = parseInt(seq_auth.substring(0, 8), 16);
        stream.sequenceRX = parseInt(seq_auth.substring(8, 16), 16);

        if(self.cipher)
        	stream.cipher = self.cipher;

        self.streams[stream.nid] = stream;
    }

    // Server
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
                data = JSON.parse(decrypt(data, stream.cipher, self.pk));
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
            stream.nid = data.designation ? data.node+'-'+data.designation : data.node;
            stream.signatures = self.signatures || data.signatures;

            var sig_auth = crypto.createHmac('sha1', self.pk).update(stream.vector).digest('hex');
            stream.sequenceRX = parseInt(sig_auth.substring(0, 8), 16);
            stream.sequenceTX = parseInt(sig_auth.substring(8, 16), 16);

        }
        catch(ex) {
            console.log("generic failure during auth:", ex.stack);
            stream.end();
            return;
        }

        self.streams[stream.nid] = stream;

        self.dispatch(stream.nid, { 
        	op : 'rpc::init', 
        	data : {
        		node : options.node || UUID.v1(),
        		designation : options.designation || ''
        	},
        	routes : _.keys(self.routes.local)
        })
    }

    // Servre & Client
    self.iface['rpc::init'] = function(msg, stream) {

		var data = msg.data;
		if(data) {    // Client
			self.dispatch({ op : 'rpc::init', routes : _.keys(self.routes.local) })

			stream.node = data.node;
			stream.designation = data.designation;
            stream.nid = data.designation ? data.node+'-'+data.designation : data.node;
		}

		_.each(msg.routes, function(nid) {
			self.routes.remote[nid] = stream;
		})

		stream.connected = true;
        self.emitToListeners('connect', stream.address, stream.nid, stream);
    }

    self.iface['rpc::online'] = function(msg, stream) {
        var nid = msg.nid;
        self.routes.remote[nid] = stream;
    }

    self.iface['rpc::offline'] = function(msg, stream) {
        delete self.routes.remote[nid];
    }

	self.on('stream::message', function(msg, stream) {

        if(config.debug)
            console.log('-->', msg);

        if(msg._sig) {
            if(config.debug)
                console.log("sequenceRX:".cyan.bold,stream.sequenceRX);
            var sig = crypto.createHmac('sha256', self.pk).update(stream.sequenceRX+'').digest('hex').substring(0, 16);
            if(msg._sig != sig) {
                console.log("should be ",sig,"is",msg._sig);
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
        if(!stream.nid) {
            console.log("zetta-rpc foreign connection "+stream.address+", closing");
            stream.end();
            return;
        }

        try {
            
            var nid = msg._r ? msg._r.nid : stream.nid;
            self.digestCallback && self.digestCallback(msg, nid, stream);
            msg.op && self.emitToListeners(msg.op, msg, nid, stream);

        } catch(ex) {
            console.error("zetta-rpc: error while processing message".magenta.bold);
            console.error(ex.stack);
        }

	})

	self.on('stream::error', function(err, stream) {
        self.emitToListeners('disconnect', stream.nid, stream);
        delete self.streams[stream.nid];
	})

	self.on('stream::end', function(stream) {
        self.emitToListeners('disconnect', stream.nid, stream);
        delete self.streams[stream.nid];
	})

    //-----

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

	self.dispatchToStream = function(stream, _msg, callback) {

        var msg = _.clone(_msg);
        if(self.routing)
            msg._nid = nid;

        if(stream.signatures) {
            if(config.debug)
                console.log("sequenceTX:".cyan.bold,stream.sequenceTX);
            msg._sig = crypto.createHmac('sha256', self.pk).update(stream.sequenceTX+'').digest('hex').substring(0, 16);
            stream.sequenceTX++;
        }
        
        if(config.debug)
            console.log('<--'.bold, msg);

        var text = JSON.stringify(msg);
        if(stream.cipher)
            text = encrypt(text, stream.cipher, self.pk);
        stream.writeTEXT(text, callback);

        return true;
	}

    self.dispatch = function (nid, msg, callback) {

    	if(_.isObject(nid)) {
    		msg = nid;
    		callback = msg;
    		nid = null;

	    	_.each(self.streams, function(stream) {
	    		self.dispatchToStream(stream, msg);
	    	})
    	}
    	else {
    		var stream = self.streams[nid];
    		if(!stream) {
	            console.error('zetta-rpc: no such stream present:'.magenta.bold, nid);
	            callback && callback(new Error("zetta-rpc: no such stream present"))
	            return;
    		}

            if(!msg) {
                console.error('zetta-rpc: dispatch() got empty message'.magenta.bold);
                callback && callback(new Error("zetta-rpc: no such stream present"))
            }
            else
            	self.dispatchToStream(stream, msg, callback);
    	}
    }

    self.response = function(msg, resp) {
        var rid = msg._rid;
    }

    self.digest = function(callback) {
        self.digestCallback = callback;
    }

    self.registerListener = function(listener) {
    	self.listeners.push(listener);
    }

    self.setPingDataObject = function(o) {
        self.pingDataObject = o;
    }

    function ping() {
        self.dispatch({ op : 'ping', data : self.pingDataObject});
        dpc(self.pingFreq, ping);
    }

    if(options.ping || options.pingFreq || options.pingDataObject) {
        dpc(function () {
            ping();
        })
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

	    if(config.verbose)
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

        var stream = new Stream(tlsStream, self, addr[0]);
        stream.address = address;
	}

    self.on('stream::error', function(err, stream) {
        dpc(1000, function() {
        	createConnection(stream.address);
        });
    })

    self.on('stream::end', function(stream) {
        dpc(1000, function() {
        	createConnection(stream.address);
        });
    })

    self.isConnected = function() {
 		for(var i in self.streams)
            return true;
        return false;
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
        stream.tlsStream.end();

    })

    // self.on('stream::end', function(stream) {
    // })
}

util.inherits(Server, Interface);


// Router - allows client->router->server (or client->router<-client) connectivity.
// This class is meant to help when a server is unable to handle maximum number
// of connections.

function Router(options) {
    var self = this;

    self.frontend = new Server({
        port : options.port, 
        auth : options.auth || options.secret,
        certificates : options.certificates,
        routing : true
    })


    // connect to relay destination
    if(options.client) {
        self.backend = new Client({
            address: options.client.address,
            auth: options.client.auth || options.client.secret || options.auth || options.secret,
            certificates: options.certificates || options.client.certificates,
            node: options.node,
            designation: 'router',
            routes : self.frontend.streams
        })
    }
    else
    if(options.server) {
        self.backend = new Server({
            port : options.server.port, 
            auth : options.server.auth || options.server.secret || options.auth || options.secret,
            certificates : options.certificates || options.server.certificates,
            routes : self.frontend.streams
        })
    }
    else
        throw new Error("zetta-rpc::Router() requires client or server")

    self.frontend.on('connect', function(address, nid, stream) {
        self.backend.dispatch({ op : 'rpc::online', nid : nid });
    })

    self.frontend.on('disconnect', function(address, nid, stream) {
        self.backend.dispatch({ op : 'rpc::offline', nid : nid });
    })

    self.backend.on('connect', function(address, nid, stream) {
        self.frontend.dispatch({ op : 'rpc::online', nid : nid });
    })

    self.backend.on('disconnect', function(address, nid, stream) {
        self.frontend.dispatch({ op : 'rpc::offline', nid : nid });
    })

    self.frontend.digest(function(msg, nid, stream) {
        msg._r = {
            nid : nid,
            designation : stream.designation,
            node : stream.node
        }

        self.backend.dispatch(msg);
    })

    self.backend.digest(function(msg, nid) {
        self.frontend.dispatch(msg._nid, msg);
    })
}


module.exports = {
	Client : Client,
	Server : Server,
    Router : Router,
    config : config
}

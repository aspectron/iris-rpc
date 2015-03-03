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
var colors = require('colors');
var crypto = require('crypto');
var events = require('events');
var util = require('util');
var UUID = require('node-uuid');

if(!GLOBAL.dpc)
    GLOBAL.dpc = function(t,fn) { if(typeof(t) == 'function') setTimeout(t,0); else setTimeout(fn,t); }

var RPC_VERSION = 1;

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
    self.iface = iface;
	self.buffer = '';
    self.address = tlsStream._host || address;
    self.serverName = tlsStream.servername;
    self.pending = { }


    if(iface.rejectUnauthorized && !tlsStream.authorized)
        return tlsStream.end();

    iface.connectionCount++;

    tlsStream.setEncoding('utf8');

    tlsStream.on('data', function (data) {
        /*if (self.buffer.length + data.length > 1024 * 65) {
            self.buffer = data;
        }*/

        self.buffer += data;

        var idx = self.buffer.indexOf('\n');
        while(~idx) {
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
                break;
            }
            
            idx = self.buffer.indexOf('\n');
        }

    });

    tlsStream.on('error', function (err) {
    	iface.connectionCount--;
//        if(config.verbose)
        if(config.verbose || err.code != 'ECONNREFUSED')
            console.log("zetta-rpc tls stream error:", err/*.message*/, ' | ' ,self.iface.designation+'@'+self.address);
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
//        if(config.debug)
//            console.log('<--'.bold,msg);
        self.tlsStream.write(JSON.stringify(msg) + '\n');
        return true;
    }

    self.writeTEXT = function(text, callback) {
        // console.log(text);
        //if(config.debug)
            //console.log('<--',text);
        self.tlsStream.write(text + '\n', callback);
        return true;
    }
}


function Interface(options) {
	var self = this;
    events.EventEmitter.call(this);

    if(!options.certificates)
        throw new Error("zetta-rpc options - missing 'certificates' argument");
    if(!options.auth && !options.secret)
        throw new Error("zetta-rpc options - missing 'auth' argument");
    if(!options.uuid)
        throw new Error("zetta-rpc options - missing 'uuid' argument");
//    if(!options.mac)
//        throw new Error("zetta-rpc options - mac is required");
// console.log("UUID".bold,options.uuid);

    // console.log("Creating RPC instance:".green.bold, options);

    self.uuid = options.uuid;
    self.designation = options.designation;
    self.mac = options.mac;
    self.filters = [ ]
    self.listeners_ = [ self ]
    self.streams = { }
    // self.pending = { }
    self.timeout = options.timeout || 60 * 1000;
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
        stream.writeJSON({ 
            op : 'rpc::auth::challenge', 
            v : RPC_VERSION,
            vector : vector 
        });
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
            v : RPC_VERSION,
            cipher : self.cipher ? encrypt(self.cipher, 'aes-256-cbc', self.pk) : false,
        }

        var data = { 
            // op : 'auth', 
            auth : auth, 
            signatures : self.signatures,
            uuid : self.uuid,
            mac : self.mac,
//            node : options.node || UUID.v1(), 
            designation : self.designation || ''
        }

        // console.log("RPC CLIENT SENDING INIT DATA:".blue.bold, data);

        msg.data = self.cipher ? encrypt(JSON.stringify(data), 'aes-256-cbc', self.pk) : data;

        stream.writeJSON(msg);

        stream.signatures = self.signatures;
        var seq_auth = crypto.createHmac('sha1', self.pk).update(vector).digest('hex');
        stream.sequenceTX = parseInt(seq_auth.substring(0, 8), 16);
        stream.sequenceRX = parseInt(seq_auth.substring(8, 16), 16);

        if(self.cipher)
        	stream.cipher = self.cipher;

//        self.streams[stream.uuid] = stream;
    }

    // Server
    self.iface['rpc::auth::response'] = function(msg, stream) {
        try {

            var data = msg.data;
            if(!data) {
                console.log("zetta-rpc auth packet missing data (peer at "+stream.address+"):", msg);
                stream.end();
                return;
            }

            if(msg.cipher) {
                stream.cipher = decrypt(msg.cipher, 'aes-256-cbc', self.pk);
                data = JSON.parse(decrypt(data, stream.cipher, self.pk));
            }

            // console.log("RPC SERVER RECEIVING INIT DATA:".blue.bold, data);


            if(!data.uuid || !data.auth) {
                console.log("zetta-rpc auth packet missing auth, uuid or designation (peer at "+stream.address+"):", data);
                stream.end();
                return;
            }

            var auth = crypto.createHmac('sha256', self.pk).update(stream.vector).digest('hex');
            if(auth != data.auth) {
                console.log("zetta-rpc auth failure:", data);
                stream.end();
                return;
            }

            stream.uuid = data.uuid;
            stream.mac = data.mac;
            //stream.node = data.node;
            stream.designation = data.designation;
            //stream.nid = data.designation ? data.node+'-'+data.designation : data.node;
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

        // console.log(("SERVER CONNECTING STREAM "+stream.uuid).green.bold);
        self.streams[stream.uuid] = stream;

        self.dispatch(stream.uuid, { 
        	op : 'rpc::init', 
            v : RPC_VERSION,
        	data : {
                uuid : self.uuid,
                mac : self.mac,
        		//node : options.node || UUID.v1(),
        		designation : self.designation || ''
        	},
        	routes : _.keys(self.routes.local)
        })
    }

    // Servre & Client
    self.iface['rpc::init'] = function(msg, stream) {

		var data = msg.data;
		if(data) {    // Client

            stream.uuid = data.uuid;
            stream.mac = data.mac;
			//stream.node = data.node;
			stream.designation = data.designation;
            //stream.uuid = data.designation ? data.node+'-'+data.designation : data.node;

            // console.log(("CLIENT CONNECTING STREAM "+stream.uuid).green.bold);
            self.streams[stream.uuid] = stream;

            self.dispatch(stream.uuid, { 
                op : 'rpc::init', 
                v : RPC_VERSION,
                routes : _.keys(self.routes.local) 
            })
		}

		_.each(msg.routes, function(uuid) {
			self.routes.remote[uuid] = stream;
		})

		stream.connected = true;
        self.emitToListeners('connect', stream.address, stream.uuid, stream);
    }

    self.iface['rpc::online'] = function(msg, stream) {
        //var nid = msg.nid;
        self.routes.remote[msg.uuid] = stream;
    }

    self.iface['rpc::offline'] = function(msg, stream) {
        delete self.routes.remote[uuid];
    }

	self.on('stream::message', function(msg, stream) {

        // if(config.debug)
            // console.log('-->', msg);

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
        if(!stream.uuid) {
            console.log("zetta-rpc foreign connection "+stream.address+", closing");
            stream.end();
            return;
        }

        if(!self.filters.length)
            return digestMessage(msg, stream);

        var filters = self.filters.slice();
        
        _digest();

        function _digest() {
            var filter = filters.shift();
            if(!filter)
                return digestMessage(msg, stream);

            filter.call(self, msg._req ? msg.req : msg, stream, function(err, disallow) {
                if(err)
                    return _fail(err);

                if(disallow)
                    return _fail(disallow);

                _digest();
            })
        }

        function _fail(err) {
            if(msg._req) {
                self.dispatchToStream(stream, {
                    _resp : msg._req,
                    err : err
                });
            }
        }
    })

    function digestMessage(msg, stream) {
        try 
        {
            
            if(msg._req) {
                var listeners = self.listeners(msg.req.op);
                if(listeners.length == 1) {
                    //var emitted = self.emit(
                    try {
                        listeners[0].call(self, msg.req, function(_err, resp) {
                            var err = (_err instanceof Error) ? {
                                    _Error : true,
                                    name : _err.name,
                                    message : _err.message,
                                    stack : _err.stack,
                                } : _err;

                            self.dispatchToStream(stream, {
                                _resp : msg._req,
                                err : err,
                                resp : resp,
                            });
                        })
                    } catch(ex) {
                        console.log("responding with error".red.bold,ex);
                        self.dispatchToStream(stream, {
                            _resp : msg._req,
                            err : ex
                        });
                    }
                }
                else
                if(listeners.length)
                {
                    self.dispatchToStream(stream, {
                        _resp : msg._req,
                        err : { error : "Too many handlers for '"+msg.req.op+"'" }
                    });
                }
                else
                {
                    self.dispatchToStream(stream, {
                        _resp : msg._req,
                        err : { error : "No such handler '"+msg.req.op+"'" }
                    });
                }
            }
            else
            if(msg._resp) {
                var pending = stream.pending[msg._resp];
                if(pending) {
                    try {

                        var err = msg.err;
                        if(err && err._Error) {
                            err = GLOBAL[msg.err.name] ? new GLOBAL[msg.err.name](msg.err.message) : new Error(msg.err.message);
                            err.stack = msg.err.stack;
                        }

                        pending.callback(err, msg.resp);
                    }
                    catch(ex) {
                        console.error("Error in callback for response:",msg);
                        console.error(ex.stack);
                    }
                    delete stream.pending[msg._resp];
                }
                else {
                    console.error('zetta-rpc: no pending callback for response:'.magenta.bold, msg);
                }
            }
            else
            {
                var uuid = msg._r ? msg._r.uuid : stream.uuid;
                self.digestCallback && self.digestCallback(msg, uuid, stream);
                msg.op && self.emitToListeners(msg.op, msg, uuid, stream);
            }

        } catch(ex) {
            console.error("zetta-rpc: error while processing message".magenta.bold);
            console.error(ex.stack);
            self.emitToListeners('rpc::error', ex, msg);
        }
	}

	self.on('stream::error', function(err, stream) {

        if(err.code != 'ECONNREFUSED')
            self.emitToListeners('disconnect', stream.uuid, stream);
        pendingCleanup(stream);
        // console.log(("RPC DISCONNECTING STREAM "+stream.uuid).green.bold);
        delete self.streams[stream.uuid];
	})

	self.on('stream::end', function(stream) {
        self.emitToListeners('disconnect', stream.uuid, stream);
        pendingCleanup(stream);
        // console.log(("RPC DISCONNECTING STREAM "+stream.uuid).green.bold);
        delete self.streams[stream.uuid];
	})

    //-----

    self.emitToListeners = function() {
        var args = arguments;
        _.each(self.listeners_, function(listener) {
            try {
                listener.emit.apply(listener, args);
            } catch(ex) {
                console.error("zetta-rpc: error while processing message".magenta.bold);
                console.error(ex.stack);
                self.emitToListeners('rpc::error', ex);
            }
        })
    }

	self.dispatchToStream = function(stream, _msg, callback) {
        var msg = null;

        if(callback) {
            var req_uuid = UUID.v1();
            // msg._req = req_uuid;
            stream.pending[req_uuid] = {
                uuid : req_uuid,
                req : _msg,
                callback : callback,
                ts : Date.now(),
            }

            msg = {
                _req : req_uuid,
                req : _msg
            }
        }
        else
            msg = _.clone(_msg);


        if(self.routing)
            msg._uuid = stream.uuid;

        if(stream.signatures) {
            if(config.debug)
                console.log("sequenceTX:".cyan.bold,stream.sequenceTX);
            msg._sig = crypto.createHmac('sha256', self.pk).update(stream.sequenceTX+'').digest('hex').substring(0, 16);
            stream.sequenceTX++;
        }
        
//        if(config.debug)
//            console.log('<--'.bold, msg);



        var text = JSON.stringify(msg);
        if(stream.cipher)
            text = encrypt(text, stream.cipher, self.pk);
        // if(msg.op != 'ping') console.log("sending text...",msg);
        stream.writeTEXT(text);

        return true;
	}

    self.dispatch = function (uuid, msg, callback) {
    	if(_.isObject(uuid)) {
    		callback = msg;
            msg = uuid;
    		uuid = null;

            if(callback && !_.size(self.streams)) {
                return callback({ error : "RPC stream is not connected", disconnected : true, req : msg });
            }
            else
            if(callback && _.size(self.streams) > 1) {
                return callback({ error : "Multiple streams connected (not supported by RPC)", req : msg });
            }

	    	_.each(self.streams, function(stream, uuid) {
                // console.log(("dispatching to stream "+uuid).cyan.bold+("  op: "+msg.op).bold+" (multi)");
	    		self.dispatchToStream(stream, msg, callback);
	    	})
    	}
    	else {
            // console.log(("dispatching to stream "+uuid).cyan.bold+("  op: "+msg.op).bold+" (single)");
    		var stream = self.streams[uuid];
    		if(!stream) {
	            console.error('zetta-rpc: no such stream present:'.magenta.bold, uuid);
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

    self.filter = function(callback) {
        self.filters.push(callback);
    }

    self.digest = function(callback) {
        self.digestCallback = callback;
    }

    self.registerListener = function(listener) {
    	self.listeners_.push(listener);
    }

    self.setPingDataObject = function(o) {
        self.pingDataObject = o;
    }

    self.ping = function() {
        self.dispatch({ op : 'ping', data : self.pingDataObject});
    }

    function ping() {
        self.ping();
        dpc(self.pingFreq, ping);
    }

    if(options.ping || options.pingFreq || options.pingDataObject) {
        dpc(function () {
            ping();
        })
    }

    function pendingCleanup(stream) {
        _.each(stream.pending, function(pending) {
            pending.callback.call(self, { error : "Connection Terminated", disconnected : true, req : pending.req } );
        })
    }

    function timeoutMonitor() {
        var ts = Date.now();
        var purge = [ ]
        _.each(self.streams, function(stream) {
            _.each(stream.pending, function(pending, uuid) {
                if(ts - pending.ts > self.timeout) {
                    pending.callback.call(self, { error : "Connection Timed Out", timeout : self.timeout, req : pending.req } );
                    purge.push({ stream : stream, uuid : uuid });
                }
            })
        })

        _.each(purge, function(o) {
            delete o.stream.pending[o.uuid];
        })

        dpc(1000, timeoutMonitor);
    }

    timeoutMonitor();

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
            console.log('zetta-rpc '+self.designation+' connected to server @'+address+', SSL certificate is', tlsStream.authorized ? 'authorized' : 'unauthorized');
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


function Multiplexer(options, config, rpcTitle) {
    var self = this;
    self.active = { }
    self.links = createFromConfig(options, config, rpcTitle);
//    if(!_.isArray(self.links))
//        self.links = [ self.links ];
//    console.log("links:",self.links);

    self.on = function(op, callback) {
        _.each(self.links, function(rpc) {
            rpc.on(op, callback);
        })
    }

    self.on('connect', function(address, uuid, stream) {
        self.active[uuid] = stream;
    })

    self.on('disconnect', function(uuid, stream) {
        delete self.active[uuid];
    })

    self.registerListener = function(listener) {
        _.each(self.links, function(rpc) {
            rpc.registerListener(listener);
        })
    }

    self.dispatch = function() {
        var args = arguments;
        _.each(self.links, function(rpc) {
            rpc.dispatch.apply(rpc, args);
        })
    }
}

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
            //node: options.node,
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

    self.frontend.on('connect', function(address, uuid, stream) {
        self.backend.dispatch({ op : 'rpc::online', uuid : uuid });
    })

    self.frontend.on('disconnect', function(uuid, stream) {
        self.backend.dispatch({ op : 'rpc::offline', uuid : uuid });
    })

    self.backend.on('connect', function(address, uuid, stream) {
        self.frontend.dispatch({ op : 'rpc::online', uuid : uuid });
    })

    self.backend.on('disconnect', function(uuid, stream) {
        self.frontend.dispatch({ op : 'rpc::offline', uuid : uuid });
    })

    self.frontend.digest(function(msg, uuid, stream) {
        msg._r = {
            uuid : uuid,
            designation : stream.designation,
            uuid : stream.uuid
        }

        self.backend.dispatch(msg);
    })

    self.backend.digest(function(msg, uuid) {
        self.frontend.dispatch(msg._uuid, msg);
    })
}

function createFromConfig(options, config, rpcTitle) {

    function createInstance(options, config, rpcTitle) { // rpcConfig) {
        var rpcConfig = _.extend({ }, options);
        _.extend(rpcConfig, config);
        if(!rpcConfig.port && !rpcConfig.address) {
            console.error("Error:".red.bold,rpcConfig);
            throw new Error("port or address required in rpc config");
        }
        if(rpcConfig.port && rpcConfig.address) {
            console.error("Error:".red.bold,rpcConfig);
            throw new Error("both port and address present in rpc config");
        }
        if(rpcConfig.port) {
            return new Server(rpcConfig, function(err) {
                console.log((rpcTitle.toUpperCase()+" RPC").bold+" server listening on",(rpcConfig.port+'').bold);    
            });
        }
        else {
            return new Client(rpcConfig);
        }
    }

    if(config.address || config.port) {
        var ret = { }
        ret[rpcTitle] = createInstance(options, config, rpcTitle || options.designation);
        return ret;
    }
    else {
        var ret = { }
        _.each(config, function(rpcConfig, rpcTitle) {
            ret[rpcTitle] = createInstance(options, rpcConfig, rpcTitle);
        })
        return ret;
    }
}

module.exports = {
	Client : Client,
	Server : Server,
    Multiplexer : Multiplexer,
    Router : Router,
    createFromConfig : createFromConfig,
    config : config
}

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


    self.connected = false;
    self.buffer = '';
    self.address = options.address.split(':');
    self.infoObject = { }
    self.pingFreq = options.pingFreq || 3 * 1000;
    self.verbose = options.verbose || zetta_rpc_default_verbose;

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
                    digest(JSON.parse(msg));
                }
                catch (ex) {
                    console.log(ex);
                    self.stream.end();
                }
            }

        });
        self.stream.on('error', function (err) {
            if(self.verbose && self.connected)
                console.log("zetta-rpc tls stream error:", err.message);

            self.connected = false;
            self.auth = false;
            dpc(1000, connect);
            self.emit('disconnect', self.stream);
        });
        self.stream.on('end', function () {
            if(self.verbose)
                console.log("zetta-rpc tls stream closed");
            self.connected = false;
            self.auth = false;
            dpc(1000, connect);
            self.emit('disconnect', self.stream);
        });
    }

    self.dispatch = function (msg) {
        if (!self.connected || !self.auth)
            return false;
        self.stream.write(JSON.stringify(msg) + '\n');
        return true;
    }

    function digest(msg) {

        if(msg.op == 'auth') {
            var vector = msg.vector;
            if(!vector) {
                console.log("zetta-rpc: no vector in auth message");
                self.stream.end();
                return;
            }

            var auth = crypto.createHmac('sha256', options.auth).update(vector).digest('hex');
            self.auth = true;
            self.dispatch({ op : 'auth', auth : auth, node : options.node, designation : options.designation });
            return;
        }

        self.digestCallback && self.digestCallback(msg);
        self.emit('message', msg, stream);
    }

    self.digest = function(callback) {
        self.digestCallback = callback;
    }


//    self.digest = function (msg) {
//        core.emit(msg.op, msg);
//    }

    self.setInfoObject = function(o) {
        self.infoObject = o;
    }

    function ping() {
//        if(!self.infoObject.nid)
//            self.infoObject.nid = core.node_id;
        self.dispatch(self.infoObject);
        dpc(self.pingFreq, ping);
    }

    dpc(connect);

    if(options.ping) {
        dpc(function () {
            ping();
        })
    }

}

util.inherits(Client, events.EventEmitter);


function Multiplexer(options) { //address_list, certificate_path, node_id, designation) {
    var self = this;
    self.servers = { }

    if(_.isArray(options.address)) {
        _.each(options.address, function (address) {
            var clientOptions = { }
            _.extend(clientOptions, options);
            clientOptions.address = address;
            console.log("init rpc @" + clientOptions.address.bold);
            self.servers[clientOptions.address] = new Client(clientOptions);
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

    self.setInfoObject = function(o) {
        _.each(self.servers, function (server) {
            server.setInfoObject(o);
        })
    }

    self.digest = function(callback) {
        _.each(self.servers, function (server) {
            server.digest(callback);
        })
    }
}


function Server(options, init_callback) { // port, certificates) {
	var self = this;
    events.EventEmitter.call(this);

	self.streams = { };
	self.connectionCount = 0;
    self.verbose = options.verbose || zetta_rpc_default_verbose;

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
                    digest(JSON.parse(msg), stream);
                }
                catch (ex) {
                    console.log(ex);
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
// console.log(msg);
        if(msg.op == 'auth-request') {
            var vector = crypto.createHash('sha256').update(JSON.stringify(Date.now()+'-'+Math.random())).digest('hex');
            stream.__vector__ = vector;
            stream.write(JSON.stringify({ op : 'auth', vector : vector })+'\n');
            return;
        }

        if(msg.op == 'auth') {
            if(!msg.node || !msg.designation || !msg.auth) {
                console.log("zetta-rpc auth packet missing auth, node or designation:", msg);
                stream.end();
                return;
            }

            var auth = crypto.createHmac('sha256', options.auth).update(stream.__vector__).digest('hex');
            if(auth != msg.auth) {
                console.log("zetta-rpc auth failure:", msg);
                stream.end();
                return;
            }

            stream.__node__ = msg.node;
            stream.__designation__ = msg.designation;
            stream.__client_id__ = msg.designation+'-'+msg.node;

            //if(self.verbose)
            //    console.log("zetta-rpc auth success:",msg);

            self.streams[stream.__client_id__] = stream;

            self.connectionCount++;
            self.emit('connect', stream, msg.designation, msg.node, stream.servername, stream.__client_id__);

            return;
        }

        if(!stream.__client_id__) {
            console.log("zetta-rpc foreign connection, closing");
            stream.end();
            return;
        }

        msg.node = stream.__node__;
        msg.designation = stream.__designation__;
        self.digestCallback(msg, stream, stream.__client_id__);
    }

    function disconnect(stream) {
        self.connectionCount--;
        delete self.streams[stream.__client_id__];
        self.emit('disconnect', stream, stream.__client_id__);
    }

    self.dispatch = function(designation, node, msg, callback) {
        var client_id = designation+'-'+node;
        var stream = self.streams[client_id];
        if(!stream)
            return false;
        stream.write(JSON.stringify(msg) + '\n');
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
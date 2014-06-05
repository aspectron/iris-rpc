var fs = require('fs');
var events = require('events');
var util = require('util');
var fs = require('fs');
var getmac = require('getmac');
var zrpc = require('../zetta-rpc');
var UUID = require('node-uuid');

function Server(mac) {
	var self = this;
	self.clients = { }
	self.port = 4488;

    self.certificates = {
        key: fs.readFileSync(__dirname + '/certificates/example.key').toString(),
        cert: fs.readFileSync(__dirname + '/certificates/example.crt').toString(),
        ca: [ ]
    }

	self.rpc = new zrpc.Server({
        uuid : UUID.v1(),
		port : self.port, 
		auth : "f72d7c54d7354f7a8f9d111c6033b6281e7096acc4dcb198763a4555f264259d",
		certificates : self.certificates,
		node : mac
	}, function(err) {
    	console.log('RPC server listening on',(self.port+'').bold);			
	});

//	console.log("RPC",self.rpc);

    // ---

	self.rpc.on('ping', function(msg, cid, designation, node) {
		console.log("Server::ping - ".bold, "cid:".bold, cid, "message:".bold, msg);
		var client = self.clients[cid];
		console.log("responding with 'pong'");
		self.rpc.dispatch(cid, { op : 'pong', ts : Date.now() })
	})

	self.rpc.on('connect', function(address, cid, designation, node, stream) {
		console.log("binding client "+cid.bold+" at "+address.green.bold);

		var client = self.clients[cid];
		if(!client) {
			client = self.clients[cid] = {
				designation : designation,
				node : node,
				address : address,
				online : true
			}
		}
		else
			client.online = true;
	})

	self.rpc.on('disconnect', function(cid, stream) {
		var client = self.clients[cid];
		if(client) {
			console.log("dropping client  "+cid.bold+" at "+client.address.magenta.bold);
			client.online = false;
		}
	})

	self.rpc.digest(function(msg) {
		console.log("Server::digest() - ".bold, msg);
	})
}


function Client(mac) {
    var self = this;
    events.EventEmitter.call(this);
    self.pingDataObject = {
        iteration : 0
    }

    self.certificates = {
        key: fs.readFileSync(__dirname + '/certificates/example.key').toString(),
        cert: fs.readFileSync(__dirname + '/certificates/example.crt').toString(),
        ca: [ ]
    }

//    var rpc = new zrpc.Multiplexer({
    var rpc = new zrpc.Client({
        uuid : UUID.v1(),
        address: ["127.0.0.1:4488"], //, "127.0.0.1:4488", "127.0.0.1:4488" ],
        auth: "f72d7c54d7354f7a8f9d111c6033b6281e7096acc4dcb198763a4555f264259d",
        certificates: self.certificates,
        // node: mac,
        designation: 'example',
        pingFreq: 3 * 1000,
        pingDataObject : self.pingDataObject
    });

    // register us as external listener (for `self.on()` processing)
    rpc.registerListener(self);

    // ---

    // listen using Multiplexer rpc object
    rpc.on('pong', function(msg) {
        console.log("Multiplexer::pong - ".bold,msg);
    })

    // listen using external listener
    self.on('pong', function(msg) {
        console.log("Client::pong - ".bold,msg);
    })

    // listen for raw JSON objects using digest() callback
    rpc.digest(function(msg, rpc) {
        console.log("Client::digest() - ".bold, msg)
    })

    setInterval(function() {
        // console.log("connected:",rpc.isConnected())
        //console.log("dispatching hello")
        var msg = { op : 'hello '};
        console.log("Client() - ".bold+" - dispatching:",msg)
        rpc.dispatch(msg);
    }, 1 * 1000)

    setInterval(function() {
        self.pingDataObject.iteration++;
        self.pingDataObject.ts = Date.now();
    }, 100)
}

util.inherits(Client, events.EventEmitter);


// obtain node id (mac of the first network adaptor)
getmac.getMac(function (err, mac) {
    if (err)
        throw err;

    mac = mac.split(process.platform == 'win32' ? '-' : ':').join('').toLowerCase();
    GLOBAL.application = {
    	server : new Server(mac),
    	client : new Client(mac)
    }
})

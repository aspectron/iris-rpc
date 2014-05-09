var fs = require('fs');
var zrpc = require('../zetta-rpc');

function Server() {
	var self = this;
	self.clients = { }
	self.port = 4488;

    self.certificates = {
        key: fs.readFileSync(__dirname + '/certificates/example.key').toString(),
        cert: fs.readFileSync(__dirname + '/certificates/example.crt').toString(),
        ca: [ ]
    }

	self.rpc = new zrpc.Server({
		port : self.port, 
		auth : "f72d7c54d7354f7a8f9d111c6033b6281e7096acc4dcb198763a4555f264259d",
		certificates : self.certificates,
	}, function(err) {
    	console.log('RPC server listening on',(self.port+'').bold);			
	});
	
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
		console.log('disconnect');
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

GLOBAL.application = new Server();
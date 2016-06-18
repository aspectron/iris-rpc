# IRIS Framework - JSON RPC over TLS

[![dependencies Status](https://david-dm.org/aspectron/iris-rpc.svg)](https://david-dm.org/aspectron/iris-rpc#info=dependencies)
[![license:mit](https://img.shields.io/badge/license-mit-blue.svg)](https://opensource.org/licenses/MIT)

IRIS-RPC is a part of [IRIS Framework](https://github.com/aspectron/iris-app).

#### Security Features:

- Uses TLS (SSL) for data transport
- HMAC based authentication against user-supplied secret
- Optional message signing against MITM attacks
- Optional second layer message encryption (aes-256-cbc by default, if enabled)

Authentication is based on user supplied secret keys, so this is as secure as your host.


## Usage

`npm install iris-rpc`


### Messaging

IRIS RPC library allows sending of JSON objects between client and server. If these JSON objects contain an opcode (`op` field), they will be emitted to the registered event listeners as well as on the RPC objects themselves (Client, Server and Multiplexer).  If `op` field is missing, `rpc.digest(function(msg) { ... })` must be used to capture transmission of incoming JSON objects.

### Client

```javascript
var irisRPC = require('iris-rpc');

var rpc = new irisRPC.Client({		// or zrpc.Client() for connection to a single server
    address: "host:port",				
    auth: "user-supplied-secret-key",   // must match opposite side
    certificates: ...,					// standard node certificates containing 'key', 'cert', 'ca' data, typically core.certificates
    uuid: "...",  						// uuid of the node, typically core.uuid
    designation: 'user-application-id',	// named identifier that is available during connection on the opposite side
    ping: true,							// optional: enable automatic server ping (see Client::setPingDataObject())
    pingFreq : 3 * 1000,				// optional: ping frequency (default 3 seconds)
    pingDataObject : ...,				// this object will be transmitted during ping
    cipher: true,						// optional: 'true' or name of cipher algorithm for 2nd layer encryption 
    									// (default 'aes-256-cbc' if true)
    signatures: true					// optional: enable message signing
});


// receive messages
rpc.on('user-message', function(msg, rpc) { ... })	

// receive messages with external event emitter
rpc.registerListener(eventEmitter);		// register event emitter that will receive messages
eventEmitter.on('user-message', function(msg, rpc) { ... })	

// send messages or JSON objects
rpc.dispatch({ op : 'user-message ', ... })	

// receive each message as JSON
rpc.digest(function(msg, rpc) { ... })

```

### Server

```javascript
var irisRPC = require('iris-rpc');

var rpc = new irisRPC.Server({
	port : 12345, 						// listening port
	auth : "user-supplied-secret-key",
    certificates: ...,					// standard node certificates containing 'key', 'cert', 'ca' data
}, function(err) {
	console.log('iris-rpc server is listening for new connections');
});

// client connection event: cid is a unique remote end-point identifier (built from designation+node)
rpc.on('connect', function(address, cid, stream) { ... })

// client disconnection event
rpc.on('disconnect', function(cid, stream) { ... })

// receive messages
rpc.on('user-message', function(msg, cid, stream) { ... })

// send messages
rpc.dispatch(cid, { op : 'user-message' })

// receive JSON objects (without 'op' field)
rpc.digest(function(msg, cid, stream) { ... })
```

### Multiplexer

Multiplexer allows creation of a single RPC interface that can combine multiple Client and/or Server RPC instances while providing a common interface for message dispatch and reception.

When configuring multiplexer, arguments are supplied as follows:
* RPC parameters (passed on to underlying Client and Server instances)
* List of connectsions
* Verbose title of the RPC link

If list of connections contains `port` key, Multiplexer will create an underlying Server instance, for `address` key, it will create underlying Client instance.

```javascript

var connectionList = {
    client1 : {
        address : "<ip>:<port>",
        auth : "<auth-string-matching-opposite-side>"
    },
    client2 : {
        address : "<ip>:<port>",
        auth : "<auth-string-matching-opposite-side>"
    },
    server1 : {
        address : <port>,
        auth : "<auth-string-matching-opposite-side>"
    },
    server2 : {
        address : <port>,
        auth : "<auth-string-matching-opposite-side>"
    },
    ...
}

self.rpc = new irisRPC.Multiplexer({
    uuid : core.uuid,
    certificates: core.certificates,
    designation: '<rpc-link-identification>',
}, connectionList, "RPC TITLE");

```

### Router

Router interface is designed for large-scale systems that require a lot of
simultaneous connections.  Linux systems are by default configured to allow between 128 
and 1024 simultaneous TCP connections.  This number can be increased, but ultimately
you may need to scale horizontally using additional servers.

Router acts as a message relay between Server and Client.

Example:
```javascript
var router = zrpc.Router({
	port : 6699,                       // Server instance configuration
	auth : "172d7c54d7354f7a1f9d161c6033b6281e7096acc4dcb198763a4555f264259d",
	certificates : core.certificates,
	client : {                         // Client instance configuration
		address : "127.0.0.1:4488",
        auth : "172d7c54d7354f7a1f9d161c6033b6281e7096acc4dcb198763a4555f264259d",
		uuid : self.uuid
	}
})
```


zetta-rpc
=========

# Zetta Toolkit: JSON RPC over TLS

This library offers clear-text JSON RPC over TLS with optional second layer encryption.

#### Security Features:

- Uses TLS (SSL) for data transport
- HMAC based authentication against user-supplied secret
- Optional message signing against MITM attacks
- Optional second layer message encryption (aes-256-cbc by default, if enabled)

Authentication is based on user supplied secret keys, so this is as secure as your host.

## Usage

`npm install zetta-rpc`


### Messaging

Zetta RPC library allows sending of JSON objects between client and server. If these JSON objects contain an opcode (`op` field), they will be emitted to the registered event listeners as well as on the RPC objects themselves (Client, Server and Multiplexer).  If `op` field is missing, `rpc.digest(function(msg) { ... })` must be used to capture transmission of incoming JSON objects.

### Client

```javascript
var zrpc = require('zetta-rpc');

var rpc = new zrpc.Multiplexer({		// or zrpc.Client() for connection to a single server
    address: "host:port",				// or multiple servers specified as ["host:port",...]  (Multiplexer only)
    auth: "user-supplied-secret-key",
    certificates: ...,					// standard node certificates containing 'key', 'cert', 'ca' data
    node: "...",  						// id of this node instance (typically host mac address)
    designation: 'user application-id',	// name of the application (used to differentiate connections coming from the same host)
    ping: true,							// optional: enable automatic server ping (see Client::setPingDataObject())
    pingFreq : 3 * 1000,				// optional: ping frequency (default 3 seconds)
    cipher: true,						// optional: 'true' or name of cipher algorithm for 2nd layer encryption 
    									// (default 'aes-256-cbc' if true)
    signatures: true					// optional: enable message signing
});

rpc.setPingDataObject(pingDataObject);	// this object will be transmitted during ping
rpc.registerListener(eventEmitter);		// register event emitter that will receive messages

// receive messages
eventEmitter.on('user-message', function(msg, rpc) { ... })	

// send messages or JSON objects
rpc.dispatch({ op : 'user-message ', ... })	

// receive JSON
rpc.digest(function(msg, rpc) { ... })

```
zrpc.Multiplexer() and zrpc.Client() provide same initialization interface. Multiplexer, however, supports an array of addresses allowing client to connect to multiple servers simultaneously.

### Server

```javascript
var zrpc = require('zetta-rpc');

var rpc = new zrpc.Server({
	port : 12345, 						// listening port
	auth : "user-supplied-secret-key",
    certificates: ...,					// standard node certificates containing 'key', 'cert', 'ca' data
}, function(err) {
	console.log('zetta-rpc server is listening for new connections');
});

// client connection event: cid is a unique remote end-point identifier (built from designation+node)
rpc.on('connect', function(address, cid, designation, node, stream) { ... })

// client disconnection event
rpc.on('disconnect', function(cid, stream) { ... })

// receive messages
rpc.on('user-message', function(msg, cid [, designation, node, stream]) { ... })

// send messages
rpc.dispatch(cid, { op : 'user-message' })

// receive JSON objects (without 'op' field)
rpc.digest(function(msg, cid [, designation, node, stream]) { ... })
```

### License

This library is a part of Zetta Toolkit, released under MIT license.  
Copyright (c) 2014 ASPECTRON Inc.  
All Rights Reserved.
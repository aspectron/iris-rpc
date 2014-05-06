zetta-rpc
=========

# Zetta Toolkit: JSON RPC over TLS

This library offers clear-text JSON RPC over TLS with optional second layer encryption.

#### Security Features:

- Uses TLS (SSL) for data transport
- HMAC based authentication against user-supplied secret
- Optional message signing against MITM attacks
- Optional message encryption (aes-256-cbc by default)

Authentication is based on user supplied secret keys, so this is as secure as your host.

## Usage

`npm install zetta-rpc`

### Client

```
var zrpc = require('zetta-rpc');

var rpc = new zrpc.Multiplexer({		// or zrpc.Client() for connection to a single server
    address: "host:port",				// or multiple servers specified as ["host:port",...]  (Multiplexer only)
    auth: "user-supplied-secret-key",
    certificates: ...,					// standard node certificates containing 'key', 'cert', 'ca' data
    node: "...",  						// id of this node instance (typically host mac address)
    designation: 'user application-id',	// name of the application (used to differentiate connections coming from the same host)
    ping: true,							// optional: enable automatic server ping (see Client::setPingDataObject())
    pingFreq : 3 * 1000,				// optional: ping frequency (default 3 seconds)
    cipher: 'aes-256-cbc',				// optional: enable cipher algorithm for 2nd layer encryption (default 'aes-256-cbc')
    signatures: true					// optional: enable message signing
});

rpc.setPingDataObject(pingDataObject);	// this object will be transmitted during ping
rpc.registerListener(eventEmitter);		// register event emitter that will receive messages

eventEmitter.on('user-message', function(msg, rpc) { ... })

```
zrpc.Multiplexer() and zrpc.Client() provide same initialization interface. Multiplexer, however, supports an array of addresses allowing client to connect to multiple servers simultaneously.

### Server

```
var zrpc = require('zetta-rpc');

var rpc = new zrpc.Server({
	port : 12345, 						// listening port
	auth : "user-supplied-secret-key",
    certificates: ...,					// standard node certificates containing 'key', 'cert', 'ca' data
}, function(err) {
	console.log('zetta-rpc server is listening for new connections');
});

rpc.on('user-message', function(msg) { ... })
```


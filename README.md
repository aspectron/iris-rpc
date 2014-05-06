zetta-rpc
=========

# Zetta Toolkit: JSON RPC over TLS

This library offers clear-text JSON RPC over TLS with optional second layer encryption.

#### Security Features:

- Uses TLS (SSL) for data transport
- HMAC based authentication against user-supplied secret
- Message signing against MITM attacks
- Optional message encryption (aes-256-cbc by default)


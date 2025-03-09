# Simplified SSL

This project provides a simplified framework for secure server-client communication,
encapsulating the core concepts of cryptographic operations, secure sockets, and encrypted data
transmission. The design incorporates custom implementations of SSL/TLS protocols, RSA
encryption/decryption, one-time key XOR encryption, and basic hashing for ensuring the
integrity and confidentiality of the data exchanged between the server and clients. Here's a brief
overview of each component's role within the project


## RSA Encryption:
 The RSA classes are central to the project's security features, enabling public-key encryption and
 decryption. They allow secure sharing of encryption keys over an insecure network, ensuring
 that data can be encrypted by the public key and only decrypted by the corresponding private
 key. This mechanism is crucial for establishing a secure initial handshake between the client and
 server, exchanging session keys, and verifying identities.

## Hash Function:
 The custom Hash class provides data integrity verification, ensuring that data transmitted over
 the network has not been tampered with. By using a hash function that processes the data
 alongside a pattern and additional parameters, both the client and the server can generate and
 verify hashes of the data they send and receive, adding an extra layer of security to their
 communication.

## One-Time Key XOR Encryption:
 The OneTimeKey class facilitates the generation of one-time keys and the encryption/decryption
 of data using the XOR operation. This technique offers a simple yet effective method for
 encrypting data with a key that is as long as the message, ensuring that the encryption is secure
 as long as the key remains secret and is used only once.

## Secure Sockets (SSLSocket and SSLServerSocket):
 The custom SSL sockets (SSLSocket and SSLServerSocket) simulate SSL/TLS functionality,
 providing a secure channel for data transmission over the network. These classes wrap standard
 Java sockets, adding layers of encryption (via RSA and one-time keys) and data integrity (via
 hashing) to the data being transmitted. They handle the encryption and decryption of data
 streams transparently, allowing the client and server to communicate securely without worrying
 about the underlying cryptographic operations.

## Server:
 The Server class sets up a secure server that listens for incoming SSL connections from clients. It
 performs a handshake to securely exchange cryptographic parameters and establishes an encrypted communication channel with each client. The server handles multiple client
 connections concurrently, processing and responding to client requests securely.

## Client:
 The Client class demonstrates how a client can establish a secure connection with the server,
 performing a handshake to exchange cryptographic parameters and establish an encrypted
 communication channel. The client can then securely send and receive data to and from the
 server.

## Contacting the Real Server
 The server's public key is used to encode the client's identity. The matching private key is needed
 to decrypt the client's identity and the proposed onetime key.

## How To Run ?

Open the Command prompt at the src directory

```bash
jar-xvf SSLproject.jar
```

### Part A

```python
java security.RSA-help
java-Dprime_size=500 security.RSA-gen "hello world"
```

### Part B

```python
java security.Hash
java security.Hash 13 2 131 7 hello
java security.OneTimeKey
java security.OneTimeKey xyz 123abc
```

## References

Refer to project report for detailed guide

# reServ

table of contents:
- [1. About](#1-about)
- [2. Dependencies](#2-dependencies)
- [3. Tasks](#3-tasks)
  - [3.1 Basic WebSocket Server Features](#31-basic-websocket-server-features)
  - [3.2 Advanced WebSocket Server Features](#32-advanced-websocket-server-features)
  - [3.3 Basic nostr Relay Features](#33-basic-nostr-relay-features)
  - [3.4 Advanced nostr Relay Features](#34-advanced-nostr-relay-features)
- [4. Bugs and Testing](#4-bugs-and-testing)

## 1. About

reServ is a WebSocket <b>relay Server</b>, written in modern C++ with the purpose of being used as a nostr relay in the future. 

The server is leveraging the Linux/Unix socket and networking facilities to provide solid WebSocket communication. The project focus is on very specialized (nostr tailored) and performant WebSocket communication, with probably little general-purpose use or customization options.

Details about nostr and its protocol can be found here:
- The [official website](https://nostr.com/)
- The [basic idea](https://nostr.how/en/what-is-nostr) of nostr and its [initial description](https://fiatjaf.com/nostr.html)
- The [implementation details](https://github.com/nostr-protocol/nips) on github (NIPs)

## 2. Dependencies

|Library        |Source               |Branch         |Info                                                           |
|---------------|---------------------|---------------|--------------------------------------------------------------|
|OpenSSL        |linux installation*  |`---`          |Toolkit for general-purpose cryptography (e.g. SHA1, BASE64)   |
|Catch2         |git submodule        |`devel`        |Simple and modern Unit testing framework for C++               |

*linux installation:
- run `sudo apt install libssl-dev` (or apt-get)
- CMake will use the system wide installation (find_package(OpenSSL REQUIRED))
- Easiest way, due to multiple problems including the git directly as a submodule


## 3. Tasks

### 3.1 Basic WebSocket Server Features

- [ ] **Finish the Core Logic: Input**: Fully implement the WebSocket Protocol and correctly parse messages
- [ ] **Finish the Core Logic: Connection**: Update the connection logic, allow for endpoint handling
- [ ] **Finish the Core Logic: Output**: Implement a basic (default) output that includes "echo" and "broadcast"
- [ ] **Finish the Core Logic: Tests**: : Unit Tests for all parts of the Core Logic!
- [ ] **Load Balancing**: Vertical/Internal Load Balancing by adding concurrency (threat pools) 
- [ ] **Message Rate Limiting**: Prevent clients from spamming a high volume of messages
- [ ] **Connection Limiting**: Restrict the number of concurrent WebSocket connections from a single client
- [ ] **Ping/Pong Frames**: Check if the connection is still alive by adding the WS ping/pong implementation
- [ ] **Binary and Text Data Handling**: Handle both binary and text data as incoming messages (WS supports both)
- [ ] **Message Size Limiting**: Limit the size of incoming messages to prevent server overload
- [ ] **Compression**: Reduce the size of data being transmitted (WebSocket protocol supports per-message compression!)
- [ ] **Logging and Monitoring**: Better logs and real-time monitoring capabilities (access logging, audit logging)
- [ ] **Origin Checks**: Verifies the origin of WebSocket requests (prevent cross-site WebSocket hijacking)

### 3.2 Advanced WebSocket Server Features

- [ ] **IPv6 Support**: Fully implement IPv6 handling (might already work out of the box, but probably not)
- [ ] **Secure WebSocket (WSS) Support**: Provide encrypted communication for WebSockets, similar to HTTPS for HTTP.
- [ ] **Multiplexing**: Allows for multiple logical channels over a single TCP connection (Not natively supported by WebSocket protocol)

### 3.3 Basic nostr Relay Features

- [ ] **[NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)**: Basic protocol, event, flow
- [ ] ...

### 3.4 Advanced nostr Relay Features

- [ ] ...

## 4. Bugs and Testing

BUG severity: 🟢 LOW | 🟡 MED | 🔴 HIGH


- [ ] 🟡 BUG: Sometimes, on closing a client connection the final message is not handled correctly
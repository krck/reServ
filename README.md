# reServ

table of contents:
- [1. About](#1-about)
- [2. Dev Dependencies](#2-dev-dependencies)
- [3. Dev Testing](#3-dev-testing)
  - [3.1 WebSocket Protocol](#31-websocket-protocol)
- [4. Tasks](#4-tasks)
  - [4.1 Basic WebSocket Server Features](#41-basic-websocket-server-features)
  - [4.2 Advanced WebSocket Server Features](#42-advanced-websocket-server-features)
  - [4.3 Basic nostr Relay Features](#43-basic-nostr-relay-features)
  - [4.4 Advanced nostr Relay Features](#44-advanced-nostr-relay-features)
- [5. Bugs and Issues](#5-bugs-and-issues)

## 1. About

reServ is a WebSocket <b>relay Server</b>, written in modern C++ with the purpose of being used as a nostr relay in the future. 

The server is leveraging the Linux/Unix socket and networking facilities to provide solid WebSocket communication. The project focus is on very specialized (nostr tailored) and performant WebSocket communication, with probably little general-purpose use or customization options.

Details about the WebSocket protocol can be found in/on:
- The [official RFC documentation](https://www.rfc-editor.org/rfc/rfc6455)
- The [mdn web docs tutorial](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers)

Details about nostr and its protocol can be found here:
- The [official website](https://nostr.com/)
- The [basic idea](https://nostr.how/en/what-is-nostr) of nostr and its [initial description](https://fiatjaf.com/nostr.html)
- The [implementation details](https://github.com/nostr-protocol/nips) on github (NIPs)

## 2. Dev Dependencies

|Library        |Source               |Branch         |Info                                                           |
|---------------|---------------------|---------------|--------------------------------------------------------------|
|OpenSSL        |linux installation*  |`---`          |Toolkit for general-purpose cryptography (e.g. SHA1, BASE64)   |
|Catch2         |git submodule        |`devel`        |Simple and modern Unit testing framework for C++               |

*linux installation:
- run `sudo apt install libssl-dev` (or apt-get)
- CMake will use the system wide installation (find_package(OpenSSL REQUIRED))
- Easiest way, due to multiple problems including the git directly as a submodule

## 3. Dev Testing

### 3.1 WebSocket Protocol

The verification of the WebSocket Protocol implementation is done with the [autobahn-testsuite](https://github.com/crossbario/autobahn-testsuite). Since this is based on python2 (which is no longer easily accessible), the best setup is in the provided docker container.

Install the docker engine with [this official guide](https://docs.docker.com/engine/install/)
(To check on running docker containers use `docker ps` and to kill a running docker container use `docker stop` with the id from ps)

<b>Execute a full test-suite run:</b>
- First cd to the `./test/autobahn` directory
- It might be necessary to change the configured IP for your docker installation:
    - Run `ip -4 addr show docker0 | grep -Po 'inet \K[\d.]+'` to get your local docker host ip
    - In the `./test/autobahn/config/fuzzingclient.json` file, replace the server url with your local docker host ip
- Start the reServ Server on the port configured in `fuzzingclient.json`
- Run (as su): `docker run -it --rm -v "${PWD}/config:/config" -v "${PWD}/reports:/reports" -u $(id -u):$(id -g) crossbario/autobahn-testsuite wstest -m fuzzingclient -s /config/fuzzingclient.json`
    - On the very first run, the docker container will be downloaded and setup automatically
    - Again, this only works in the `./test/autobahn` directory, to get the correct path mappings
- The test output will be written to the `./test/autobahn/reports` directory


## 4. Tasks

### 4.1 Basic WebSocket Server Features

- [x] **Finish the Core Logic: Input**: Fully implement the WebSocket Protocol and correctly parse messages
- [x] **Finish the Core Logic: Connection**: Update the connection logic, allow for endpoint handling
- [ ] **Finish the Core Logic: Output**: Implement a basic (default) output that includes "echo" and "broadcast"
- [ ] **Finish the Core Logic: WebSocket Protocol**: Handle all basic WebSocket functionalities, as specified by the Protocol
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

### 4.2 Advanced WebSocket Server Features

- [ ] **IPv6 Support**: Fully implement IPv6 handling (might already work out of the box, but probably not)
- [ ] **Secure WebSocket (WSS) Support**: Provide encrypted communication for WebSockets, similar to HTTPS for HTTP.
- [ ] **Multiplexing**: Allows for multiple logical channels over a single TCP connection (Not natively supported by WebSocket protocol)

### 4.3 Basic nostr Relay Features

- [ ] **[NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)**: Basic protocol, event, flow
- [ ] ...

### 4.4 Advanced nostr Relay Features

- [ ] ...

## 5. Bugs and Issues

BUG severity: 🟢 LOW | 🟡 MED | 🔴 HIGH


- [ ] 🟡 BUG: Sometimes, on closing a client connection the final message is not handled correctly
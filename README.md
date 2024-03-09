# reServ

table of contents:
- [reServ](#reserv)
  - [About](#about)
  - [Dependencies](#dependencies)


## About

reServ is a WebSocket <b>relay Server</b>, written in modern C++ with the purpose of being used as a nostr relay in the future. 

The server is leveraging the Linux/Unix socket and networking facilities to provide solid WebSocket communication. The project focus is on very specialized (nostr tailored) and performant WebSocket communication, with probably little general-purpose use or customization options.

## Dependencies

|Library        |Source               |Branch         |Info                                                           |
|---------------|---------------------|---------------|---------------------------------------------------------------|
|OpenSSL        |linux installation*  |`---`          |Toolkit for general-purpose cryptography (e.g. SHA1, BASE64)   |
|Catch2         |git submodule        |`devel`        |Simple and modern Unit testing framework for C++               |

*linux installation:
- run `sudo apt install libssl-dev` (or apt-get)
- CMake will use the system wide installation (find_package(OpenSSL REQUIRED))
- Easiest way, due to multiple problems including the git directly as a submodule

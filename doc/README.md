Globe Core
=============

Setup
---------------------
Globe Core is the original Globe client and it builds the backbone of the network. It downloads and, by default, stores the entire history of Globe transactions, which requires a few gigabytes of disk space. Depending on the speed of your computer and network connection, the synchronization process can take anywhere from a few hours to a day or more.

To download Globe Core, visit [globe.io](https://globe.io/downloads/).

Running
---------------------
The following are some helpful notes on how to run Globe Core on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/globe-qt` (GUI) or
- `bin/globed` (headless)

### Windows

Unpack the files into a directory, and then run globe-qt.exe.

### macOS

Drag Globe Core to your applications folder, and then run Globe Core.

### Need Help?

* See the documentation at the [Globe Wiki](https://globe.wiki/start)
for help and more information.
* Ask for help on [#globe](https://riot.im/app/#/room/#globe:matrix.org) on Riot.
* Ask for help on [Discord](https://discord.me/globe).

Building
---------------------
The following are developer notes on how to build Globe Core on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)
- [FreeBSD Build Notes](build-freebsd.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [NetBSD Build Notes](build-netbsd.md)
- [Android Build Notes](build-android.md)

Development
---------------------
The Globe repo's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Productivity Notes](productivity.md)
- [Release Process](release-process.md)
- [Source Code Documentation (External Link)](https://doxygen.globecore.org/)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [Travis CI](travis-ci.md)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Shared Libraries](shared-libraries.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)
- [Internal Design Docs](design/)

### Resources
* Discuss on [GlobeTalk](https://globetalk.org/index.php?topic=1835782.0) forums.
* Discuss project-specific development on [#globe](https://riot.im/app/#/room/#globe-dev:matrix.org) on Riot.

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [globe.conf Configuration File](globe-conf.md)
- [CJDNS Support](cjdns.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [I2P Support](i2p.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [Managing Wallets](managing-wallets.md)
- [Multisig Tutorial](multisig-tutorial.md)
- [P2P bad ports definition and list](p2p-bad-ports.md)
- [PSBT support](psbt.md)
- [Reduce Memory](reduce-memory.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Transaction Relay Policy](policy/README.md)
- [ZMQ](zmq.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).

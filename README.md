sigbak
======

[sigbak][1] is a command-line utility to read the encrypted backups created by
the [Signal messaging app][2]. It can be used to extract messages and other
data.

Documentation is available in the [manual page][3].

Dependencies
------------

sigbak depends on libcrypto (from either [LibreSSL][4] >= 2.6.0 or
[OpenSSL][5] >= 1.1.0), [protobuf-c][6] and [SQLite][7]. A C compiler, make and
pkg-config are also needed.

On Debian-based distros it should suffice to install the following packages:
build-essential libprotobuf-c-dev libsqlite3-dev libssl-dev pkg-config
protobuf-c-compiler.

Building on OpenBSD
-------------------

To build sigbak on OpenBSD, run `make` and optionally `make install`.

Building on other systems
-------------------------

To build sigbak on other systems, first check out the `portable` branch:

	$ git checkout portable

Then check if config.h is suited to your system. Edit it if necessary. config.h
already has support for several systems. On those systems, no editing should be
necessary.

Finally, run `make` and optionally `make install`.

[1]: https://www.kariliq.nl/sigbak/
[2]: https://www.signal.org/
[3]: https://www.kariliq.nl/sigbak/manual.html
[4]: https://www.libressl.org/
[5]: https://www.openssl.org/
[6]: https://github.com/protobuf-c/protobuf-c
[7]: https://www.sqlite.org/

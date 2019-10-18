sigbak
======

[sigbak][1] is a command-line utility to read the encrypted backups created by
the [Signal messaging app][2]. It can be used to extract messages and other
data.

Documentation is available in the [manual page][3].

sigbak-portable
---------------

This repository contains sigbak-portable, a portable version of sigbak. sigbak
proper currently builds on OpenBSD only. sigbak-portable adds a portability
layer so that it will build on other Unix systems.

Dependencies
------------

sigbak-portable depends on [libcrypto][4], [protobuf-c][5] and [SQLite][6]. A
C compiler, make and pkg-config are also needed.

Building
--------

First check if config.h is suited to your system. Edit it if necessary.
config.h already has support for several systems. On those systems, no editing
should be necessary.

Then run `make` and, if desired, `make install`.

[1]: https://www.kariliq.nl/sigbak/
[2]: https://www.signal.org/
[3]: https://www.kariliq.nl/sigbak/manual.html
[4]: https://man.openbsd.org/crypto.3
[5]: https://github.com/protobuf-c/protobuf-c
[6]: https://www.sqlite.org/

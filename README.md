sigbak
======

[sigbak][1] is a utility to read the encrypted backups created by the [Signal
messaging app][2]. It can be used to extract messages, attachments and other
data.

Documentation is available in the `sigbak.1` manual page. You can also [read it
online][3].

Dependencies
------------

sigbak depends on libcrypto (from either [LibreSSL][4] or [OpenSSL][5]),
[protobuf-c][6] and [SQLite][7]. You will also need a C compiler, `make` and
`pkg-config`.

On Debian-based distros it should suffice to install the following packages:
build-essential libprotobuf-c-dev libsqlite3-dev libssl-dev pkg-config
protobuf-c-compiler.

Building on OpenBSD
-------------------

To build sigbak on OpenBSD, clone the repository and run `make`.

Building on other systems
-------------------------

To build sigbak on other systems, clone the repository, switch to the
`portable` branch and run `make`:

	git clone https://github.com/tbvdm/sigbak.git
	cd sigbak
	git checkout portable
	make

sigbak should build without problems on Linux and the BSDs.

If the build does fail, check if `config.h` is suited to your system. You may
have to edit it. After editing `config.h`, run `make` to retry the build.

Building on macOS
-----------------

To build sigbak on macOS, first install [Homebrew][8].

Then install the required packages, clone the repository, switch to the
`portable` branch and run `gmake`:

	brew install libressl make pkg-config protobuf-c sqlite
	git clone https://github.com/tbvdm/sigbak.git
	cd sigbak
	git checkout portable
	PKG_CONFIG_PATH=$(brew --prefix)/opt/libressl/lib/pkgconfig gmake

Reporting problems
------------------

Please report bugs and other problems with sigbak. If sigbak shows errors or
warnings unexpectedly, please report them as well. You can [open an issue on
GitHub][9] or send an email. You can find my email address at the top of the
`sigbak.c` file.

[1]: https://www.kariliq.nl/sigbak/
[2]: https://www.signal.org/
[3]: https://www.kariliq.nl/man/sigbak.1.html
[4]: https://www.libressl.org/
[5]: https://www.openssl.org/
[6]: https://github.com/protobuf-c/protobuf-c
[7]: https://www.sqlite.org/
[8]: https://brew.sh/
[9]: https://github.com/tbvdm/sigbak/issues

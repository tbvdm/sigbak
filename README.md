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

Building
--------

sigbak should build on most Unix systems. This section contains generic build
instructions. See the sections below for build instructions for specific
systems.

First install all required packages (see the "Dependencies" section above). For
example, on Debian or Ubuntu, run the following command:

	sudo apt-get install build-essential git libprotobuf-c-dev libsqlite3-dev libssl-dev pkg-config protobuf-c-compiler

After you have installed the required packages, run the following commands:

	git clone https://github.com/tbvdm/sigbak.git
	cd sigbak
	git checkout portable
	make

Building on OpenBSD
-------------------

To build sigbak on OpenBSD, run the following commands:

	doas pkg_add git protobuf-c sqlite3
	git clone https://github.com/tbvdm/sigbak.git
	cd sigbak
	make

Building on macOS
-----------------

To build sigbak on macOS, first install [Homebrew][8]. Then run the following
command:

	brew install --HEAD tbvdm/tap/sigbak

This will build and install sigbak from [my Homebrew tap][9].

If you prefer to build sigbak manually, run the following commands instead:

	brew install libressl make pkg-config protobuf-c sqlite
	git clone https://github.com/tbvdm/sigbak.git
	cd sigbak
	git checkout portable
	PKG_CONFIG_PATH=$(brew --prefix)/opt/libressl/lib/pkgconfig gmake

Building on Windows
-------------------

To build sigbak on Windows, first install [Cygwin][10]. See the [Cygwin User's
Guide][11] if you need help.

You will be able to select additional packages for installation. Ensure the
`curl`, `gcc-core`, `gcc-g++`, `git`, `libprotobuf-devel`, `libsqlite3-devel`,
`libssl-devel`, `make` and `pkg-config` packages are installed.

After the installation has completed, start the Cygwin terminal.

Unfortunately, Cygwin does not provide a package for `protobuf-c`, so you will
have to install it from source. Run the following commands:

	curl -LO https://github.com/protobuf-c/protobuf-c/releases/download/v1.3.3/protobuf-c-1.3.3.tar.gz
	tar fxz protobuf-c-1.3.3.tar.gz
	cd protobuf-c-1.3.3
	./configure --prefix=/usr/local
	make install
	cd ..
	rm -r protobuf-c-1.3.3

Now you can build and install sigbak. Run the following commands:

	git clone https://github.com/tbvdm/sigbak.git
	cd sigbak
	git checkout portable
	PKG_CONFIG_PATH=/usr/local/lib/pkgconfig make install

You can access your Windows drives through the `/cygdrive` directory. For
example:

	cd /cygdrive/c/Users/Alice/Documents
	sigbak messages signal.backup messages.txt

Reporting problems
------------------

Please report bugs and other problems with sigbak. If sigbak shows errors or
warnings unexpectedly, please report them as well. You can [open an issue on
GitHub][12] or send an email. You can find my email address at the top of the
`sigbak.c` file.

[1]: https://www.kariliq.nl/sigbak/
[2]: https://www.signal.org/
[3]: https://www.kariliq.nl/man/sigbak.1.html
[4]: https://www.libressl.org/
[5]: https://www.openssl.org/
[6]: https://github.com/protobuf-c/protobuf-c
[7]: https://www.sqlite.org/
[8]: https://brew.sh/
[9]: https://github.com/tbvdm/homebrew-tap
[10]: https://cygwin.com/
[11]: https://cygwin.com/cygwin-ug-net/setup-net.html#internet-setup
[12]: https://github.com/tbvdm/sigbak/issues

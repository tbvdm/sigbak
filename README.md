sigbak
======

[sigbak][1] is a utility to read the backups created by the [Signal Android
app][2]. It can be used to export messages, attachments and other data.

For example, the following two commands will export all messages and
attachments from the backup `signal-2022-01-23-12-34-45.backup`. Messages will
be exported to the `messages` directory and attachments to the `attachments`
directory:

	sigbak export-messages signal-2022-01-23-12-34-45.backup messages
	sigbak export-attachments signal-2022-01-23-12-34-45.backup attachments

The complete documentation is available in the `sigbak.1` manual page. You can
also [read it online][3].

Dependencies
------------

sigbak depends on libcrypto (from either [LibreSSL][4] or [OpenSSL][5]),
[protobuf-c][6] and [SQLite][7]. You will also need a C compiler, `make` and
`pkg-config`.

Building
--------

sigbak should build on most modern Unix-like systems. This section contains
generic build instructions. See the sections below for build instructions for
specific systems.

First install all required packages (see the "Dependencies" section above). For
example, on Debian or Ubuntu, run:

	sudo apt-get install build-essential git libprotobuf-c-dev libsqlite3-dev libssl-dev pkg-config protobuf-c-compiler

After you have installed the required packages, run:

	git clone https://github.com/tbvdm/sigbak.git
	cd sigbak
	git checkout portable
	make

Building on OpenBSD
-------------------

To build sigbak on OpenBSD, run:

	doas pkg_add git protobuf-c sqlite3
	git clone https://github.com/tbvdm/sigbak.git
	cd sigbak
	make

Building on macOS
-----------------

On macOS, first install [Homebrew][8]. Then install the sigbak formula from [my
Homebrew tap][9]:

	brew install --HEAD tbvdm/tap/sigbak

To update the sigbak formula, run:

	brew upgrade --fetch-HEAD sigbak

If you prefer to build sigbak manually, run:

	brew install libressl make pkg-config protobuf-c sqlite
	git clone https://github.com/tbvdm/sigbak.git
	cd sigbak
	git checkout portable
	PKG_CONFIG_PATH=$(brew --prefix libressl)/lib/pkgconfig gmake

Building on Windows
-------------------

On Windows, first install [Cygwin][10]. During the installation, you will be
given the opportunity to install additional packages. Ensure the `curl`,
`gcc-core`, `gcc-g++`, `git`, `libprotobuf-devel`, `libsqlite3-devel`,
`libssl-devel`, `make` and `pkg-config` packages are installed.

The [Cygwin User's Guide][11] might be useful if you need help with the
installation.

After the installation has completed, start the Cygwin terminal.

Unfortunately, Cygwin does not provide a package for `protobuf-c`, so you will
have to build it from source. In the Cygwin terminal, run:

	curl -LO https://github.com/protobuf-c/protobuf-c/releases/download/v1.4.1/protobuf-c-1.4.1.tar.gz
	tar fxz protobuf-c-1.4.1.tar.gz
	cd protobuf-c-1.4.1
	./configure
	make install
	cd ..
	rm -r protobuf-c-1.4.1

Now you can build sigbak. In the Cygwin terminal, run:

	git clone https://github.com/tbvdm/sigbak.git
	cd sigbak
	git checkout portable
	PKG_CONFIG_PATH=/usr/local/lib/pkgconfig make install

If you prefer, you can use [this PowerShell script][12] to install Cygwin and
sigbak automatically. Press Windows+R to open the Run window, paste the
following command and press Enter:

	powershell -nop -c "iex (iwr https://github.com/tbvdm/cygwin-install-scripts/raw/master/install-cygwin-sigbak.ps1)"

In the Cygwin terminal, you can access your Windows drives through the
`/cygdrive` directory. For example:

	cd /cygdrive/c/Users/Alice/Documents
	sigbak export-messages signal.backup messages

Reporting problems
------------------

Please report bugs and other problems with sigbak. If sigbak shows errors or
warnings unexpectedly, please report them as well. You can [open an issue on
GitHub][13] or [send an email][14].

[1]: https://github.com/tbvdm/sigbak
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
[12]: https://github.com/tbvdm/cygwin-install-scripts/raw/master/install-cygwin-sigbak.ps1
[13]: https://github.com/tbvdm/sigbak/issues
[14]: https://www.kariliq.nl/contact.html

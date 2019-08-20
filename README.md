sigbak
======

sigbak is a command-line utility to read the encrypted backups created by the
[Signal messaging app][1]. It can be used to extract messages and other data.

sigbak depends on [LibreSSL][2]'s libcrypto, [protobuf-c][3] and [SQLite][4].
In addition, it uses several OpenBSD extensions such as [explicit\_bzero(3)][5]
and [readpassphrase(3)][6]. A portability layer may be added later.

The repository is [here][7].

Documentation is available in the [manual page][8].

[1]: https://www.signal.org/
[2]: https://www.libressl.org/
[3]: https://github.com/protobuf-c/protobuf-c
[4]: https://www.sqlite.org/
[5]: https://man.openbsd.org/explicit_bzero.3
[6]: https://man.openbsd.org/readpassphrase.3
[7]: https://www.kariliq.nl/hg/sigbak/
[8]: https://www.kariliq.nl/sigbak/manual.html

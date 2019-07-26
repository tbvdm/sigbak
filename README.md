sigbak
======

sigbak is a command-line utility to read encrypted backups made by the [Signal
messaging app][1].

Signal has recently switched from plaintext exports of messages to encrypted
backups. Although this is an improvement in various respects, it also means
that Signal messages are no longer readable outside the app itself. Hence
sigbak.

sigbak depends on [LibreSSL][2]'s libcrypto, [protobuf-c][3] and [SQLite][4].
In addition, it uses several OpenBSD extensions such as [explicit\_bzero(3)][5]
and [readpassphrase(3)][6]. A portability layer will be added later.

The repository is [here][7]. A mirror is available at [Bitbucket][8].

Documentation is available in the [manual page][9].

[1]: https://www.signal.org/
[2]: https://www.libressl.org/
[3]: https://github.com/protobuf-c/protobuf-c
[4]: https://www.sqlite.org/
[5]: https://man.openbsd.org/explicit_bzero
[6]: https://man.openbsd.org/readpassphrase
[7]: https://www.kariliq.nl/hg/sigbak
[8]: https://bitbucket.org/tbvdm/sigbak
[9]: https://www.kariliq.nl/sigbak/manual.html

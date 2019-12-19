sigbak
======

[sigbak][1] is a command-line utility to read the encrypted backups created by
the [Signal messaging app][2]. It can be used to extract messages and other
data.

Documentation is available in the [manual page][3].

sigbak depends on [libcrypto][4], [protobuf-c][5] and [SQLite][6]. In addition,
it uses several OpenBSD extensions such as [explicit\_bzero(3)][7] and
[readpassphrase(3)][8].

sigbak currently builds on OpenBSD only. A portable version of sigbak is
maintained in a [separate repository][9] ([GitHub mirror][10]).

[1]: https://www.kariliq.nl/sigbak/
[2]: https://www.signal.org/
[3]: https://www.kariliq.nl/sigbak/manual.html
[4]: https://man.openbsd.org/crypto.3
[5]: https://github.com/protobuf-c/protobuf-c
[6]: https://www.sqlite.org/
[7]: https://man.openbsd.org/explicit_bzero.3
[8]: https://man.openbsd.org/readpassphrase.3
[9]: https://www.kariliq.nl/git/sigbak-portable/
[10]: https://github.com/tbvdm/sigbak-portable

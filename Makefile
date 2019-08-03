PROG=		sigbak
SRCS=		backup.pb-c.c mem.c sbk.c sigbak.c
BUILDFIRST=	backup.pb-c.h
CLEANFILES=	backup.pb-c.c backup.pb-c.h

COPTS+!=	pkg-config --cflags libcrypto libprotobuf-c sqlite3
LDADD+!=	pkg-config --libs libcrypto libprotobuf-c sqlite3

backup.pb-c.c backup.pb-c.h: backup.proto
	protoc --c_out=. backup.proto

.include <bsd.prog.mk>

PROG=		sigbak
SRCS=		backup.pb-c.c cmd-attachments.c cmd-dump.c cmd-messages.c \
		cmd-sqlite.c mem.c sbk.c sigbak.c
BUILDFIRST=	backup.pb-c.h
CLEANFILES=	backup.pb-c.c backup.pb-c.h

CFLAGS+=	-I.
CFLAGS+!=	pkg-config --cflags libprotobuf-c sqlite3

LDADD+=		-lcrypto
LDADD+!=	pkg-config --libs libprotobuf-c sqlite3

backup.pb-c.c backup.pb-c.h: backup.proto
	protoc --c_out=. --proto_path=${.CURDIR} backup.proto

.include <bsd.prog.mk>

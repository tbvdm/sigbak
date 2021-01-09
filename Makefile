PROG=		sigbak
SRCS=		backup.pb-c.c cmd-attachments.c cmd-check.c cmd-dump.c \
		cmd-messages.c cmd-sqlite.c cmd-threads.c database.pb-c.c \
		mem.c protobuf.c sbk.c sigbak.c

LDADD+=		-lcrypto

.if !(make(clean) || make(cleandir) || make(obj))
CFLAGS+!=	pkg-config --cflags sqlite3
LDADD+!=	pkg-config --libs sqlite3
.endif

.include <bsd.prog.mk>

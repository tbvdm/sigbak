PROG=		sigbak
SRCS=		cmd-check-backup.c cmd-dump-backup.c cmd-export-attachments.c \
		cmd-export-avatars.c cmd-export-database.c \
		cmd-export-messages.c cmd-list-conversations.c mime.c sbk.c \
		sigbak.c
PROTOS=		backup.proto database.proto

SRCS+=		${PROTOS:.proto=.pb-c.c}
BUILDFIRST=	${PROTOS:.proto=.pb-c.h}
CLEANFILES=	${PROTOS:.proto=.pb-c.c} ${PROTOS:.proto=.pb-c.h}

CFLAGS+=	-I.
LDADD+=		-lcrypto

.if !(make(clean) || make(cleandir) || make(obj))
CFLAGS+!=	pkg-config --cflags libprotobuf-c sqlite3
LDADD+!=	pkg-config --libs libprotobuf-c sqlite3
.endif

.SUFFIXES: .pb-c.c .pb-c.h .proto

.proto.pb-c.c .proto.pb-c.h:
	protoc --c_out=. --proto_path=${.CURDIR} $<

.include <bsd.prog.mk>

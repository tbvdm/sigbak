PREFIX?=	/usr/local
BINDIR?=	${PREFIX}/bin
MANDIR?=	${PREFIX}/man

CC?=		cc
INSTALL?=	install
PKG_CONFIG?=	pkg-config
PROTOC?=	protoc-c

LIBCRYPTO_PKG?=		libcrypto
LIBPROTOBUF_C_PKG?=	libprotobuf-c
SQLITE3_PKG?=		sqlite3

PKGS?=		${LIBCRYPTO_PKG} ${LIBPROTOBUF_C_PKG} ${SQLITE3_PKG}

PKG_CFLAGS!=	${PKG_CONFIG} --cflags ${PKGS}
PKG_LDFLAGS!=	${PKG_CONFIG} --libs ${PKGS}

CFLAGS+=	${PKG_CFLAGS}
LDFLAGS+=	${PKG_LDFLAGS}

PROTOS=		backup.proto database.proto
PROTO_HDRS=	${PROTOS:.proto=.pb-c.h}
PROTO_SRCS=	${PROTOS:.proto=.pb-c.c}
PROTO_OBJS=	${PROTO_SRCS:.c=.o}

COMPAT_OBJS=	compat/asprintf.o compat/err.o compat/explicit_bzero.o \
		compat/fopen.o compat/getprogname.o compat/hkdf.o \
		compat/hmac_ctx_new.o compat/pledge.o compat/readpassphrase.o \
		compat/reallocarray.o compat/strtonum.o compat/unveil.o

OBJS=		cmd-check-backup.o cmd-dump-backup.o cmd-export-attachments.o \
		cmd-export-avatars.o cmd-export-database.o \
		cmd-export-messages.o cmd-threads.o mime.o sbk.o sigbak.o \
		${PROTO_OBJS} ${COMPAT_OBJS}

.PHONY: all clean install

.SUFFIXES:
.SUFFIXES: .c .pb-c.o .o .pb-c.c .pb-c.h .proto

.c.o .pb-c.c.pb-c.o:
	${CC} ${CFLAGS} ${CPPFLAGS} -c -o $@ $<

.proto.pb-c.c .proto.pb-c.h:
	${PROTOC} --c_out=. $<

all: sigbak

sigbak: ${OBJS}
	${CC} -o $@ ${OBJS} ${LDFLAGS}

${OBJS}: config.h ${PROTO_HDRS}

clean:
	rm -f sigbak sigbak.core core ${PROTO_SRCS} ${PROTO_HDRS} ${OBJS}

install: all
	${INSTALL} -dm 755 ${DESTDIR}${BINDIR}
	${INSTALL} -dm 755 ${DESTDIR}${MANDIR}/man1
	${INSTALL} -m 555 sigbak ${DESTDIR}${BINDIR}
	${INSTALL} -m 444 sigbak.1 ${DESTDIR}${MANDIR}/man1

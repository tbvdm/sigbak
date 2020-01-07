PREFIX?=	/usr/local
BINDIR?=	${PREFIX}/bin
MANDIR?=	${PREFIX}/man/man1

CC?=		cc
INSTALL?=	install
PKG_CONFIG?=	pkg-config
PROTOC?=	protoc-c

PKGS?=		libcrypto libprotobuf-c sqlite3

PKGS_CFLAGS!=	${PKG_CONFIG} --cflags ${PKGS}
PKGS_LDFLAGS!=	${PKG_CONFIG} --libs ${PKGS}

CFLAGS+=	${PKGS_CFLAGS}
LDFLAGS+=	${PKGS_LDFLAGS}

OBJS=		backup.pb-c.o cmd-attachments.o cmd-check.o cmd-dump.o \
		cmd-messages.o cmd-sqlite.o cmd-threads.o mem.o sbk.o sigbak.o

OBJS+=		compat/asprintf.o compat/err.o compat/explicit_bzero.o \
		compat/fopen.o compat/freezero.o compat/hkdf.o \
		compat/pledge.o compat/readpassphrase.o compat/reallocarray.o \
		compat/recallocarray.o compat/strtonum.o compat/unveil.o

.PHONY: all clean install

.SUFFIXES: .c .o

all: sigbak

sigbak: ${OBJS}
	${CC} -o $@ ${OBJS} ${LDFLAGS}

${OBJS}: backup.pb-c.h config.h

backup.pb-c.c backup.pb-c.h: backup.proto
	${PROTOC} --c_out=. backup.proto

.c.o:
	${CC} ${CFLAGS} ${CPPFLAGS} -c -o $@ $<

clean:
	rm -f sigbak sigbak.core core backup.pb-c.c backup.pb-c.h ${OBJS}

install: sigbak
	${INSTALL} -dm 755 ${DESTDIR}${BINDIR}
	${INSTALL} -dm 755 ${DESTDIR}${MANDIR}
	${INSTALL} -m 555 sigbak ${DESTDIR}${BINDIR}
	${INSTALL} -m 444 sigbak.1 ${DESTDIR}${MANDIR}

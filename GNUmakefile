PREFIX?=	/usr/local
BINDIR?=	$(PREFIX)/bin
MANDIR?=	$(PREFIX)/man/man1

INSTALL?=	install
PROTOC?=	protoc

CFLAGS+=	$(shell pkg-config --cflags libcrypto libprotobuf-c sqlite3)
LDFLAGS+=	$(shell pkg-config --libs libcrypto libprotobuf-c sqlite3)

OBJS=		backup.pb-c.o cmd-attachments.o cmd-dump.o cmd-messages.o \
		cmd-sqlite.o mem.o sbk.o sigbak.o

OBJS+=		compat/asprintf.o compat/err.o compat/explicit_bzero.o \
		compat/fopen.o compat/freezero.o compat/hkdf.o \
		compat/pledge.o compat/readpassphrase.o compat/reallocarray.o \
		compat/recallocarray.o compat/unveil.o

.PHONY: all clean install

all: sigbak

sigbak: $(OBJS)

$(OBJS): backup.pb-c.h

backup.pb-c.c backup.pb-c.h: backup.proto
	$(PROTOC) --c_out=. backup.proto

clean:
	rm -f sigbak sigbak.core core backup.pb-c.c backup.pb-c.h $(OBJS)

install: sigbak
	$(INSTALL) -dm 755 $(DESTDIR)$(BINDIR)
	$(INSTALL) -dm 755 $(DESTDIR)$(MANDIR)
	$(INSTALL) -m 555 sigbak $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 444 sigbak.1 $(DESTDIR)$(MANDIR)

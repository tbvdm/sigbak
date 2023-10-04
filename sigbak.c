/*
 * Copyright (c) 2018 Tim van der Molen <tim@kariliq.nl>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <libgen.h>
#include <readpassphrase.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sigbak.h"

extern const struct cmd_entry cmd_check_backup_entry;
extern const struct cmd_entry cmd_dump_backup_entry;
extern const struct cmd_entry cmd_export_attachments_entry;
extern const struct cmd_entry cmd_export_avatars_entry;
extern const struct cmd_entry cmd_export_database_entry;
extern const struct cmd_entry cmd_export_messages_entry;
extern const struct cmd_entry cmd_export_stickers_entry;

static const struct cmd_entry *commands[] = {
	&cmd_check_backup_entry,
	&cmd_dump_backup_entry,
	&cmd_export_attachments_entry,
	&cmd_export_avatars_entry,
	&cmd_export_database_entry,
	&cmd_export_messages_entry,
	&cmd_export_stickers_entry
};

__dead static void
usage(const char *cmd, const char *args)
{
	fprintf(stderr, "usage: %s %s %s\n", getprogname(), cmd, args);
	exit(1);
}

int
get_passphrase(const char *passfile, char *buf, size_t bufsize)
{
	int	 fd;
	ssize_t	 len;
	char	*c, *d;

	if (bufsize == 0)
		return -1;

	if (passfile == NULL) {
		if (readpassphrase("Enter 30-digit passphrase (whitespace is "
		    "ignored): ", buf, bufsize, 0) == NULL) {
			warnx("Cannot read passphrase");
			explicit_bzero(buf, bufsize);
			return -1;
		}
	} else {
		if ((fd = open(passfile, O_RDONLY)) == -1) {
			warn("%s", passfile);
			return -1;
		}

		if ((len = read(fd, buf, bufsize - 1)) == -1) {
			warn("%s", passfile);
			explicit_bzero(buf, bufsize);
			close(fd);
			return -1;
		}

		if ((c = memchr(buf, '\n', len)) != NULL)
			len = c - buf;

		buf[len] = '\0';
		close(fd);
	}

	/* Remove whitespace */
	for (c = d = buf; *c != '\0'; c++)
		if (!isspace((unsigned char)*c))
			*d++ = *c;
	*d = '\0';

	return 0;
}

int
unveil_dirname(const char *path, const char *perms)
{
	char *dir, *tmp;

	if ((tmp = strdup(path)) == NULL) {
		warn(NULL);
		return -1;
	}

	if ((dir = dirname(tmp)) == NULL) {
		warnx("dirname() failed");
		free(tmp);
		return -1;
	}

	if (unveil(dir, perms) == -1) {
		warn("unveil: %s", dir);
		free(tmp);
		return -1;
	}

	free(tmp);
	return 0;
}

void
sanitise_filename(char *name)
{
	char *c;

	if (strcmp(name, ".") == 0) {
		name[0] = '_';
		return;
	}

	if (strcmp(name, "..") == 0) {
		name[0] = name[1] = '_';
		return;
	}

	for (c = name; *c != '\0'; c++)
		if (*c == '/' || iscntrl((unsigned char)*c))
			*c = '_';
}

char *
get_recipient_filename(struct sbk_recipient *rcp, const char *ext)
{
	char		*fname;
	const char	*detail, *name;
	int		 ret;

	name = sbk_get_recipient_display_name(rcp);

	if (rcp->type == SBK_GROUP)
		detail = "group";
	else
		detail = rcp->contact->phone;

	if (ext == NULL)
		ext = "";

	if (detail != NULL)
		ret = asprintf(&fname, "%s (%s)%s", name, detail, ext);
	else
		ret = asprintf(&fname, "%s%s", name, ext);

	if (ret == -1) {
		warnx("asprintf() failed");
		return NULL;
	}

	sanitise_filename(fname);
	return fname;
}

int
main(int argc, char **argv)
{
	const struct cmd_entry	*cmd;
	size_t			 i;

	if (argc < 2)
		usage("command", "[argument ...]");

	argc--;
	argv++;
	cmd = NULL;

	for (i = 0; i < nitems(commands); i++)
		if (strcmp(argv[0], commands[i]->name) == 0 ||
		    strcmp(argv[0], commands[i]->alias) == 0) {
			cmd = commands[i];
			break;
		}

	if (cmd == NULL)
		errx(1, "%s: Invalid command", argv[0]);

	switch (cmd->exec(argc, argv)) {
	case CMD_OK:
		return 0;
	case CMD_ERROR:
		return 1;
	case CMD_USAGE:
		usage(cmd->name, cmd->usage);
		return 1;
	}
}

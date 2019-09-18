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

#include "config.h"

#include <sys/stat.h>

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "compat.h"
#include "sigbak.h"

void
usage(const char *cmd, const char *args)
{
	fprintf(stderr, "usage: %s %s %s\n", getprogname(), cmd, args);
	exit(1);
}

int
get_passphrase(const char *passfile, char *buf, size_t bufsize)
{
	FILE	*fp;
	char	*c, *d;

	if (passfile == NULL) {
		if (readpassphrase("Enter 30-digit passphrase (spaces are "
		    "ignored): ", buf, bufsize, 0) == NULL) {
			warnx("Cannot read passphrase");
			explicit_bzero(buf, bufsize);
			return -1;
		}
	} else {
		if ((fp = fopen(passfile, "r")) == NULL) {
			warn("%s", passfile);
			return -1;
		}

		if (fgets(buf, bufsize, fp) == NULL) {
			if (ferror(fp))
				warn("%s", passfile);
			else
				warnx("%s: Empty file", passfile);

			explicit_bzero(buf, bufsize);
			fclose(fp);
			return -1;
		}

		fclose(fp);
		buf[strcspn(buf, "\n")] = '\0';
	}

	/* Remove spaces */
	for (c = d = buf; *c != '\0'; c++)
		if (*c != ' ')
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
		warn("dirname");
		free(tmp);
		return -1;
	}

	if (unveil(dir, perms) == -1) {
		warn("unveil");
		free(tmp);
		return -1;
	}

	free(tmp);
	return 0;
}

int
main(int argc, char **argv)
{
	if (argc < 2) {
		usage("command", "[argument ...]");
		return 1;
	}

	argc--;
	argv++;

	if (strcmp(argv[0], "attachments") == 0)
		return cmd_attachments(argc, argv);
	if (strcmp(argv[0], "avatars") == 0)
		return cmd_avatars(argc, argv);
	if (strcmp(argv[0], "dump") == 0)
		return cmd_dump(argc, argv);
	if (strcmp(argv[0], "messages") == 0)
		return cmd_messages(argc, argv);
	if (strcmp(argv[0], "sqlite") == 0)
		return cmd_sqlite(argc, argv);

	errx(1, "%s: Invalid command", argv[0]);
}

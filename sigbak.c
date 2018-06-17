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

#include <err.h>
#include <readpassphrase.h>
#include <string.h>
#include <unistd.h>

#include "sbk.h"

void
remove_spaces(char *s)
{
	char *t;

	for (t = s; *s != '\0'; s++)
		if (*s != ' ')
			*t++ = *s;
	*t = '\0';
}

int
main(int argc, char **argv)
{
	char	passphr[128];
	int	ret;

	if (argc != 2)
		return 1;

	if (readpassphrase("Enter 30-digit passphrase (spaces are ignored): ",
	    passphr, sizeof passphr, 0) == NULL)
		errx(1, "Cannot read passphrase");

	if (pledge("stdio rpath", NULL) == -1)
		err(1, "pledge");

	remove_spaces(passphr);
	ret = sbk_dump(argv[1], passphr);
	explicit_bzero(passphr, sizeof passphr);
	return (ret == 0) ? 0 : 1;
}

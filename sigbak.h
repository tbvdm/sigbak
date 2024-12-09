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

#ifndef SIGBAK_H
#define SIGBAK_H

#include "sbk.h"

#ifndef nitems
#define nitems(a) (sizeof (a) / sizeof (a)[0])
#endif

#define FLAG_EXPORT_ALL		0x1
#define FLAG_FILENAME_ID	0x2
#define FLAG_MTIME_SENT		0x4
#define FLAG_MTIME_RECV		0x8

#define FLAG_MTIME_MASK		(FLAG_MTIME_SENT | FLAG_MTIME_RECV)


enum cmd_status {
	CMD_OK,
	CMD_ERROR,
	CMD_USAGE
};

struct cmd_entry {
	const char	*name;
	const char	*alias;
	const char	*usage;
	enum cmd_status	 (*exec)(int, char **);
};

const char	*mime_get_extension(const char *);

int		 get_passphrase(const char *, char *, size_t);
int		 unveil_dirname(const char *, const char *);
void		 sanitise_filename(char *);
char		*get_recipient_filename(struct sbk_recipient *, const char *);
char		*get_file_name(struct sbk_attachment *, int);
char		*get_attachment_field(struct sbk_attachment *, int);
int			export_attachments(struct sbk_ctx *, const char *, int);

#endif

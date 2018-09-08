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

#include "backup.pb-c.h"

struct sbk_ctx;
struct sbk_file;

enum sbk_file_type {
	SBK_ATTACHMENT,
	SBK_AVATAR
};

struct sbk_ctx	*sbk_ctx_new(void);
void		 sbk_ctx_free(struct sbk_ctx *);

int		 sbk_open(struct sbk_ctx *, const char *, const char *);
void		 sbk_close(struct sbk_ctx *);
int		 sbk_eof(struct sbk_ctx *);
int		 sbk_rewind(struct sbk_ctx *);

Signal__BackupFrame *sbk_get_frame(struct sbk_ctx *);
void		 sbk_free_frame(Signal__BackupFrame *);
int		 sbk_skip_file(struct sbk_ctx *, Signal__BackupFrame *);

struct sbk_file	*sbk_get_file(struct sbk_ctx *);
void		 sbk_free_file(struct sbk_file *);
enum sbk_file_type sbk_get_file_type(struct sbk_file *);
const char	*sbk_get_file_name(struct sbk_file *);
size_t		 sbk_get_file_size(struct sbk_file *);
int		 sbk_write_file(struct sbk_ctx *, struct sbk_file *, FILE *);

int		 sbk_write_database(struct sbk_ctx *, const char *);

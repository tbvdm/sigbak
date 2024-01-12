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

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "sbk-internal.h"

int
sbk_sqlite_open(sqlite3 **db, const char *path)
{
	if (sqlite3_open(path, db) != SQLITE_OK) {
		sbk_sqlite_warnd(*db, "Cannot open database");
		return -1;
	}

	return 0;
}

int
sbk_sqlite_exec(struct sbk_ctx *ctx, const char *sql)
{
	char *errmsg;

	if (sqlite3_exec(ctx->db, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
		warnx("Cannot execute SQL statement: %s", errmsg);
		sqlite3_free(errmsg);
		return -1;
	}

	return 0;
}

int
sbk_sqlite_prepare(struct sbk_ctx *ctx, sqlite3_stmt **stm, const char *query)
{
	if (sqlite3_prepare_v2(ctx->db, query, -1, stm, NULL) != SQLITE_OK) {
		sbk_sqlite_warn(ctx, "Cannot prepare SQL statement");
		return -1;
	}

	return 0;
}

int
sbk_sqlite_step(struct sbk_ctx *ctx, sqlite3_stmt *stm)
{
	int ret;

	ret = sqlite3_step(stm);
	if (ret != SQLITE_ROW && ret != SQLITE_DONE)
		sbk_sqlite_warn(ctx, "Cannot execute SQL statement");

	return ret;
}

int
sbk_sqlite_bind_null(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx)
{
	if (sqlite3_bind_null(stm, idx) != SQLITE_OK) {
		sbk_sqlite_warn(ctx, "Cannot bind SQL parameter");
		return -1;
	}

	return 0;
}

int
sbk_sqlite_bind_int(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx, int val)
{
	if (sqlite3_bind_int(stm, idx, val) != SQLITE_OK) {
		sbk_sqlite_warn(ctx, "Cannot bind SQL parameter");
		return -1;
	}

	return 0;
}

int
sbk_sqlite_bind_int64(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx,
    sqlite3_int64 val)
{
	if (sqlite3_bind_int64(stm, idx, val) != SQLITE_OK) {
		sbk_sqlite_warn(ctx, "Cannot bind SQL parameter");
		return -1;
	}

	return 0;
}

int
sbk_sqlite_bind_double(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx,
    double val)
{
	if (sqlite3_bind_double(stm, idx, val) != SQLITE_OK) {
		sbk_sqlite_warn(ctx, "Cannot bind SQL parameter");
		return -1;
	}

	return 0;
}

int
sbk_sqlite_bind_blob(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx,
    const void *val, size_t len)
{
	if (sqlite3_bind_blob(stm, idx, val, len, SQLITE_STATIC) !=
	    SQLITE_OK) {
		sbk_sqlite_warn(ctx, "Cannot bind SQL parameter");
		return -1;
	}

	return 0;
}

int
sbk_sqlite_bind_text(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx,
    const char *val)
{
	if (sqlite3_bind_text(stm, idx, val, -1, SQLITE_STATIC) != SQLITE_OK) {
		sbk_sqlite_warn(ctx, "Cannot bind SQL parameter");
		return -1;
	}

	return 0;
}

int
sbk_sqlite_column_text_copy(struct sbk_ctx *ctx, char **buf, sqlite3_stmt *stm,
    int idx)
{
#ifdef notyet
	const unsigned char	*txt;
	int			 len;

	*buf = NULL;

	if (sqlite3_column_type(stm, idx) == SQLITE_NULL)
		return 0;

	if ((txt = sqlite3_column_text(stm, idx)) == NULL) {
		sbk_sqlite_warn(ctx, "Cannot get column text");
		return -1;
	}

	if ((len = sqlite3_column_bytes(stm, idx)) < 0) {
		sbk_sqlite_warn(ctx, "Cannot get column size");
		return -1;
	}

	if ((*buf = malloc((size_t)len + 1)) == NULL) {
		warn(NULL);
		return -1;
	}

	memcpy(*buf, txt, (size_t)len + 1);
	return len;
#else
	const unsigned char *txt;

	*buf = NULL;

	if (sqlite3_column_type(stm, idx) == SQLITE_NULL)
		return 0;

	if ((txt = sqlite3_column_text(stm, idx)) == NULL) {
		sbk_sqlite_warn(ctx, "Cannot get column text");
		return -1;
	}

	if ((*buf = strdup((const char *)txt)) == NULL) {
		warn(NULL);
		return -1;
	}

	return 0;
#endif
}

static void
sbk_sqlite_vwarnd(sqlite3 *db, const char *fmt, va_list ap)
{
	char *msg;

	if (fmt == NULL)
		warnx("%s", sqlite3_errmsg(db));
	else {
		if (vasprintf(&msg, fmt, ap) == -1) {
			warnx("vasprintf() failed");
			return;
		}
		warnx("%s: %s", msg, sqlite3_errmsg(db));
		free(msg);
	}
}

void
sbk_sqlite_warnd(sqlite3 *db, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sbk_sqlite_vwarnd(db, fmt, ap);
	va_end(ap);
}

void
sbk_sqlite_warn(struct sbk_ctx *ctx, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	sbk_sqlite_vwarnd(ctx->db, fmt, ap);
	va_end(ap);
}

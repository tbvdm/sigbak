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

#include <inttypes.h>
#include <stdlib.h>
#include <strings.h>

#include "sbk-internal.h"

static int
sbk_bind_param(struct sbk_ctx *ctx, sqlite3_stmt *stm, int idx,
    Signal__SqlStatement__SqlParameter *par)
{
	if (par->stringparamter != NULL)
		return sbk_sqlite_bind_text(ctx, stm, idx,
		    par->stringparamter);

	if (par->has_integerparameter)
		return sbk_sqlite_bind_int64(ctx, stm, idx,
		    par->integerparameter);

	if (par->has_doubleparameter)
		return sbk_sqlite_bind_double(ctx, stm, idx,
		    par->doubleparameter);

	if (par->has_blobparameter)
		return sbk_sqlite_bind_blob(ctx, stm, idx,
		    par->blobparameter.data, par->blobparameter.len);

	if (par->has_nullparameter)
		return sbk_sqlite_bind_null(ctx, stm, idx);

	warnx("Unknown SQL parameter type");
	return -1;
}

static int
sbk_exec_statement(struct sbk_ctx *ctx, Signal__SqlStatement *sql)
{
	sqlite3_stmt	*stm;
	size_t		 i;

	if (sql->statement == NULL) {
		warnx("Invalid SQL frame");
		return -1;
	}

	/* Don't try to create tables with reserved names */
	if (strncasecmp(sql->statement, "create table sqlite_", 20) == 0)
		return 0;

	if (sbk_sqlite_prepare(ctx, &stm, sql->statement) == -1)
		return -1;

	for (i = 0; i < sql->n_parameters; i++)
		if (sbk_bind_param(ctx, stm, i + 1, sql->parameters[i]) == -1)
			goto error;

	if (sbk_sqlite_step(ctx, stm) != SQLITE_DONE)
		goto error;

	sqlite3_finalize(stm);
	return 0;

error:
	sqlite3_finalize(stm);
	return -1;
}

static int
sbk_set_database_version(struct sbk_ctx *ctx, Signal__DatabaseVersion *ver)
{
	char	*sql;
	int	 ret;

	if (!ver->has_version) {
		warnx("Invalid version frame");
		return -1;
	}

	ctx->db_version = ver->version;

	if (asprintf(&sql, "PRAGMA user_version = %" PRIu32, ver->version) ==
	    -1) {
		warnx("asprintf() failed");
		return -1;
	}

	ret = sbk_sqlite_exec(ctx, sql);
	free(sql);
	return ret;
}

int
sbk_create_database(struct sbk_ctx *ctx)
{
	Signal__BackupFrame	*frm;
	struct sbk_file		*file;
	int			 ret;

	if (ctx->db != NULL)
		return 0;

	if (sbk_sqlite_open(&ctx->db, ":memory:") == -1)
		goto error;

	if (sbk_rewind(ctx) == -1)
		goto error;

	if (sbk_sqlite_exec(ctx, "BEGIN TRANSACTION") == -1)
		goto error;

	ret = 0;

	while ((frm = sbk_get_frame(ctx, &file)) != NULL) {
		if (frm->version != NULL)
			ret = sbk_set_database_version(ctx, frm->version);
		else if (frm->statement != NULL)
			ret = sbk_exec_statement(ctx, frm->statement);
		else if (frm->attachment != NULL)
			ret = sbk_insert_attachment_entry(ctx, frm, file);
		else
			sbk_free_file(file);

		sbk_free_frame(frm);

		if (ret == -1)
			goto error;
	}

	if (sbk_sqlite_exec(ctx, "END TRANSACTION") == -1)
		goto error;

	if (ctx->state != SBK_LAST_FRAME)
		goto error;

	return 0;

error:
	sbk_free_attachment_tree(ctx);
	sqlite3_close(ctx->db);
	ctx->db = NULL;
	return -1;
}

int
sbk_write_database(struct sbk_ctx *ctx, const char *path)
{
	sqlite3		*db;
	sqlite3_backup	*bak;
	int		 ret;

	if (sbk_create_database(ctx) == -1)
		return -1;

	if (sbk_sqlite_open(&db, path) == -1)
		goto error;

	if ((bak = sqlite3_backup_init(db, "main", ctx->db, "main")) == NULL) {
		sbk_sqlite_warnd(db, "Cannot write database");
		goto error;
	}

	if ((ret = sqlite3_backup_step(bak, -1)) != SQLITE_DONE) {
		warnx("Cannot write database: %s", sqlite3_errstr(ret));
		sqlite3_backup_finish(bak);
		goto error;
	}

	sqlite3_backup_finish(bak);

	if (sqlite3_close(db) != SQLITE_OK) {
		sbk_sqlite_warnd(db, "Cannot close database");
		return -1;
	}

	return 0;

error:
	sqlite3_close(db);
	return -1;
}

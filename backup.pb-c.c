/*
 * Copyright (c) 2020 Tim van der Molen <tim@kariliq.nl>
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

#include <stdlib.h>
#include <string.h>

#include "sigbak.h"

#define VARINT_CONTINUE_BIT			0x80
#define VARINT_VALUE_MASK			0x7f

#define TAG_FIELDNUM_SHIFT			3
#define TAG_WIRETYPE_MASK			0x7

#define WIRETYPE_VARINT				0
#define WIRETYPE_64BIT				1
#define WIRETYPE_LENGTH_DELIM			2
#define WIRETYPE_32BIT				5

#define HEADER_IV_FIELD				1
#define HEADER_SALT_FIELD			2

#define SQLSTATEMENT_STATEMENT_FIELD		1
#define SQLSTATEMENT_PARAMETERS_FIELD		2

#define SQLPARAMETER_STRINGPARAMTER_FIELD	1
#define SQLPARAMETER_INTEGERPARAMETER_FIELD	2
#define SQLPARAMETER_DOUBLEPARAMETER_FIELD	3
#define SQLPARAMETER_BLOBPARAMETER_FIELD	4
#define SQLPARAMETER_NULLPARAMETER_FIELD	5

#define SHAREDPREFERENCE_FILE_FIELD		1
#define SHAREDPREFERENCE_KEY_FIELD		2
#define SHAREDPREFERENCE_VALUE_FIELD		3

#define ATTACHMENT_ROWID_FIELD			1
#define ATTACHMENT_ATTACHMENTID_FIELD		2
#define ATTACHMENT_LENGTH_FIELD			3

#define DATABASEVERSION_VERSION_FIELD		1

#define AVATAR_NAME_FIELD			1
#define AVATAR_LENGTH_FIELD			2
#define AVATAR_RECIPIENTID_FIELD		3

#define STICKER_ROWID_FIELD			1
#define STICKER_LENGTH_FIELD			2

#define BACKUPFRAME_HEADER_FIELD		1
#define BACKUPFRAME_STATEMENT_FIELD		2
#define BACKUPFRAME_PREFERENCE_FIELD		3
#define BACKUPFRAME_ATTACHMENT_FIELD		4
#define BACKUPFRAME_VERSION_FIELD		5
#define BACKUPFRAME_END_FIELD			6
#define BACKUPFRAME_AVATAR_FIELD		7
#define BACKUPFRAME_STICKER_FIELD		8

struct tag {
	uint32_t	fieldnum;
	uint8_t		wiretype;
};

static void
binarydata_init(ProtobufCBinaryData *bin)
{
	bin->len = 0;
	bin->data = NULL;
}

static size_t
varint_unpack(uint64_t *varint, size_t buflen, const uint8_t *buf)
{
	size_t i;

	*varint = 0;

	for (i = 0; i < buflen && i * 7 < 64; i++) {
		*varint |= (uint64_t)(buf[i] & VARINT_VALUE_MASK) << (i * 7);

		if ((buf[i] & VARINT_CONTINUE_BIT) == 0)
			return i + 1;
	}

	return 0;
}

static size_t
tag_unpack(struct tag *tag, size_t buflen, const uint8_t *buf)
{
	uint64_t	varint;
	size_t		n;

	n = varint_unpack(&varint, buflen, buf);
	if (n == 0 || varint > UINT32_MAX)
		return 0;

	tag->fieldnum = varint >> TAG_FIELDNUM_SHIFT;
	tag->wiretype = varint & TAG_WIRETYPE_MASK;
	return n;
}

static size_t
fieldlen_unpack(size_t *fieldlen, size_t buflen, const uint8_t *buf)
{
	uint64_t	varint;
	size_t		n;

	n = varint_unpack(&varint, buflen, buf);
	if (n == 0 || varint > buflen - n)
		return 0;

	*fieldlen = varint;
	return n;
}

static size_t
bool_unpack(protobuf_c_boolean *val, size_t buflen, const uint8_t *buf)
{
	uint64_t	varint;
	size_t		n;

	n = varint_unpack(&varint, buflen, buf);
	if (n == 0)
		return 0;

	*val = varint != 0;
	return n;
}

static size_t
uint32_unpack(uint32_t *val, size_t buflen, const uint8_t *buf)
{
	uint64_t	varint;
	size_t		n;

	n = varint_unpack(&varint, buflen, buf);
	if (n == 0 || varint > UINT32_MAX)
		return 0;

	*val = varint;
	return n;
}

static size_t
uint64_unpack(uint64_t *val, size_t buflen, const uint8_t *buf)
{
	return varint_unpack(val, buflen, buf);
}

static size_t
fixed64_unpack(uint64_t *fixed64, size_t buflen, const uint8_t *buf)
{
	if (buflen < sizeof *fixed64)
		return 0;

	*fixed64 =
	    (uint64_t)buf[0]       | (uint64_t)buf[1] <<  8 |
	    (uint64_t)buf[2] << 16 | (uint64_t)buf[3] << 24 |
	    (uint64_t)buf[4] << 32 | (uint64_t)buf[5] << 40 |
	    (uint64_t)buf[6] << 48 | (uint64_t)buf[7] << 56;

	return sizeof *fixed64;
}

static size_t
double_unpack(double *val, size_t buflen, const uint8_t *buf)
{
	uint64_t	fixed64;
	size_t		n;

	n = fixed64_unpack(&fixed64, buflen, buf);
	if (n == 0)
		return 0;

	*val = *(double *)&fixed64;
	return sizeof fixed64;
}

static char *
string_unpack(__unused ProtobufCAllocator *alloc, size_t buflen,
    const uint8_t *buf)
{
	char *str;

	if (buflen == SIZE_MAX)
		return NULL;

	str = malloc(buflen + 1);
	if (str == NULL)
		return NULL;

	memcpy(str, buf, buflen);
	str[buflen] = '\0';
	return str;
}

static size_t
binarydata_unpack(ProtobufCBinaryData *bin, __unused ProtobufCAllocator *alloc,
    size_t buflen, const uint8_t *buf)
{
	if (buflen == 0)
		bin->data = NULL;
	else {
		bin->data = malloc(buflen);
		if (bin->data == NULL)
			return 0;
		memcpy(bin->data, buf, buflen);
	}

	bin->len = buflen;
	return buflen;
}

Signal__Header *
signal__header__unpack(ProtobufCAllocator *alloc, size_t buflen,
    const uint8_t *buf)
{
	Signal__Header	*hdr;
	struct tag	 tag;
	size_t		 fieldlen, n;

	hdr = malloc(sizeof *hdr);
	if (hdr == NULL)
		return NULL;

	hdr->has_iv = 0;
	binarydata_init(&hdr->iv);
	hdr->has_salt = 0;
	binarydata_init(&hdr->salt);

	while (buflen > 0) {
		n = tag_unpack(&tag, buflen, buf);
		if (n == 0)
			goto error;

		buf += n;
		buflen -= n;

		switch (tag.fieldnum) {
		case HEADER_IV_FIELD:
			if (hdr->has_iv == 1)
				goto error;
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			if (binarydata_unpack(&hdr->iv, alloc, fieldlen, buf)
			    == 0)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;
			hdr->has_iv = 1;
			break;

		case HEADER_SALT_FIELD:
			if (hdr->has_salt == 1)
				goto error;
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			if (binarydata_unpack(&hdr->salt, alloc, fieldlen, buf)
			    == 0)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;
			hdr->has_salt = 1;
			break;

		default:
			goto error;
		}
	}

	return hdr;

error:
	signal__header__free_unpacked(hdr, alloc);
	return NULL;
}

Signal__SqlStatement__SqlParameter *
signal__sql_statement__sql_parameter__unpack(ProtobufCAllocator *alloc,
    size_t buflen, const uint8_t *buf)
{
	Signal__SqlStatement__SqlParameter *par;
	struct tag		 tag;
	size_t			 fieldlen, n;

	par = malloc(sizeof *par);
	if (par == NULL)
		return NULL;

	par->stringparamter = NULL;
	par->has_integerparameter = 0;
	par->has_doubleparameter = 0;
	par->has_blobparameter = 0;
	par->has_nullparameter = 0;

	while (buflen > 0) {
		n = tag_unpack(&tag, buflen, buf);
		if (n == 0)
			goto error;

		buf += n;
		buflen -= n;

		switch (tag.fieldnum) {
		case SQLPARAMETER_STRINGPARAMTER_FIELD:
			if (par->stringparamter != NULL)
				goto error;
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			par->stringparamter = string_unpack(alloc, fieldlen,
			    buf);
			if (par->stringparamter == NULL)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;
			break;

		case SQLPARAMETER_INTEGERPARAMETER_FIELD:
			if (par->has_integerparameter)
				goto error;
			if (tag.wiretype != WIRETYPE_VARINT)
				goto error;

			n = uint64_unpack(&par->integerparameter, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -=n;
			par->has_integerparameter = 1;
			break;

		case SQLPARAMETER_DOUBLEPARAMETER_FIELD:
			if (par->has_doubleparameter)
				goto error;
			if (tag.wiretype != WIRETYPE_64BIT)
				goto error;

			n = double_unpack(&par->doubleparameter, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;
			par->has_doubleparameter = 1;
			break;

		case SQLPARAMETER_BLOBPARAMETER_FIELD:
			if (par->has_blobparameter)
				goto error;
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			if (binarydata_unpack(&par->blobparameter, alloc,
			    fieldlen, buf) == 0)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;
			par->has_blobparameter = 1;
			break;

		case SQLPARAMETER_NULLPARAMETER_FIELD:
			if (par->has_nullparameter)
				goto error;
			if (tag.wiretype != WIRETYPE_VARINT)
				goto error;

			n = bool_unpack(&par->nullparameter, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;
			par->has_nullparameter = 1;
			break;

		default:
			goto error;
		}
	}

	return par;

error:
	signal__sql_statement__sql_parameter__free_unpacked(par, alloc);
	return NULL;
}

Signal__SqlStatement *
signal__sql_statement__unpack(ProtobufCAllocator *alloc, size_t buflen,
    const uint8_t *buf)
{
	Signal__SqlStatement	*sql;
	Signal__SqlStatement__SqlParameter *par, **newparameters;
	struct tag		 tag;
	size_t			 fieldlen, n;

	sql = malloc(sizeof *sql);
	if (sql == NULL)
		return NULL;

	sql->statement = NULL;
	sql->n_parameters = 0;
	sql->parameters = NULL;

	while (buflen > 0) {
		n = tag_unpack(&tag, buflen, buf);
		if (n == 0)
			goto error;

		buf += n;
		buflen -= n;

		switch (tag.fieldnum) {
		case SQLSTATEMENT_STATEMENT_FIELD:
			if (sql->statement != NULL)
				goto error;
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			sql->statement = string_unpack(alloc, fieldlen, buf);
			if (sql->statement == NULL)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;
			break;

		case SQLSTATEMENT_PARAMETERS_FIELD:
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			par = signal__sql_statement__sql_parameter__unpack(
			    alloc, fieldlen, buf);
			if (par == NULL)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;

			newparameters = reallocarray(sql->parameters,
			    sql->n_parameters + 1, sizeof *newparameters);
			if (newparameters == NULL) {
				signal__sql_statement__sql_parameter__free_unpacked(
				    par, alloc);
				goto error;
			}

			newparameters[sql->n_parameters++] = par;
			sql->parameters = newparameters;
			break;

		default:
			goto error;
		}
	}

	return sql;

error:
	signal__sql_statement__free_unpacked(sql, alloc);
	return NULL;
}

Signal__SharedPreference *
signal__shared_preference__unpack(ProtobufCAllocator *alloc, size_t buflen,
    const uint8_t *buf)
{
	Signal__SharedPreference	*prf;
	struct tag			 tag;
	size_t				 fieldlen, n;

	prf = malloc(sizeof *prf);
	if (prf == NULL)
		return NULL;

	prf->file = NULL;
	prf->key = NULL;
	prf->value = NULL;

	while (buflen > 0) {
		n = tag_unpack(&tag, buflen, buf);
		if (n == 0)
			goto error;

		buf += n;
		buflen -= n;

		switch (tag.fieldnum) {
		case SHAREDPREFERENCE_FILE_FIELD:
			if (prf->file != NULL)
				goto error;
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			prf->file = string_unpack(alloc, fieldlen, buf);
			if (prf->file == NULL)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;
			break;

		case SHAREDPREFERENCE_KEY_FIELD:
			if (prf->key != NULL)
				goto error;
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			prf->key = string_unpack(alloc, fieldlen, buf);
			if (prf->key == NULL)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;
			break;

		case SHAREDPREFERENCE_VALUE_FIELD:
			if (prf->value != NULL)
				goto error;
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			prf->value = string_unpack(alloc, fieldlen, buf);
			if (prf->value == NULL)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;
			break;

		default:
			goto error;
		}
	}

	return prf;

error:
	signal__shared_preference__free_unpacked(prf, alloc);
	return NULL;
}

Signal__Attachment *
signal__attachment__unpack(ProtobufCAllocator *alloc, size_t buflen,
    const uint8_t *buf)
{
	Signal__Attachment	*att;
	struct tag		 tag;
	size_t			 n;

	att = malloc(sizeof *att);
	if (att == NULL)
		return NULL;

	att->has_rowid = 0;
	att->has_attachmentid = 0;
	att->has_length = 0;

	while (buflen > 0) {
		n = tag_unpack(&tag, buflen, buf);
		if (n == 0)
			goto error;

		buf += n;
		buflen -= n;

		switch (tag.fieldnum) {
		case ATTACHMENT_ROWID_FIELD:
			if (att->has_rowid)
				goto error;
			if (tag.wiretype != WIRETYPE_VARINT)
				goto error;

			n = uint64_unpack(&att->rowid, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;
			att->has_rowid = 1;
			break;

		case ATTACHMENT_ATTACHMENTID_FIELD:
			if (att->has_attachmentid)
				goto error;
			if (tag.wiretype != WIRETYPE_VARINT)
				goto error;

			n = uint64_unpack(&att->attachmentid, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;
			att->has_attachmentid = 1;
			break;

		case ATTACHMENT_LENGTH_FIELD:
			if (att->has_length)
				goto error;
			if (tag.wiretype != WIRETYPE_VARINT)
				goto error;

			n = uint32_unpack(&att->length, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;
			att->has_length = 1;
			break;

		default:
			goto error;
		}
	}

	return att;

error:
	signal__attachment__free_unpacked(att, alloc);
	return NULL;
}

Signal__DatabaseVersion *
signal__database_version__unpack(ProtobufCAllocator *alloc, size_t buflen,
    const uint8_t *buf)
{
	Signal__DatabaseVersion	*ver;
	struct tag		 tag;
	size_t			 n;

	ver = malloc(sizeof *ver);
	if (ver == NULL)
		return NULL;

	ver->has_version = 0;

	while (buflen > 0) {
		n = tag_unpack(&tag, buflen, buf);
		if (n == 0)
			goto error;

		buf += n;
		buflen -= n;

		switch (tag.fieldnum) {
		case DATABASEVERSION_VERSION_FIELD:
			if (ver->has_version)
				goto error;
			if (tag.wiretype != WIRETYPE_VARINT)
				goto error;

			n = uint32_unpack(&ver->version, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;
			ver->has_version = 1;
			break;

		default:
			goto error;
		}
	}

	return ver;

error:
	signal__database_version__free_unpacked(ver, alloc);
	return NULL;
}

Signal__Avatar*
signal__avatar__unpack(ProtobufCAllocator *alloc, size_t buflen,
    const uint8_t *buf)
{
	Signal__Avatar		*ava;
	struct tag		 tag;
	size_t			 fieldlen, n;

	ava = malloc(sizeof *ava);
	if (ava == NULL)
		return NULL;

	ava->name = NULL;
	ava->has_length = 0;
	ava->recipientid = NULL;

	while (buflen > 0) {
		n = tag_unpack(&tag, buflen, buf);
		if (n == 0)
			goto error;

		buf += n;
		buflen -= n;

		switch (tag.fieldnum) {
		case AVATAR_NAME_FIELD:
			if (ava->name != NULL)
				goto error;
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			ava->name = string_unpack(alloc, fieldlen, buf);
			if (ava->name == NULL)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;
			break;

		case AVATAR_LENGTH_FIELD:
			if (ava->has_length)
				goto error;
			if (tag.wiretype != WIRETYPE_VARINT)
				goto error;

			n = uint32_unpack(&ava->length, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;
			ava->has_length = 1;
			break;

		case AVATAR_RECIPIENTID_FIELD:
			if (ava->recipientid != NULL)
				goto error;
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			ava->recipientid = string_unpack(alloc, fieldlen, buf);
			if (ava->recipientid == NULL)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;
			break;

		default:
			goto error;
		}
	}

	return ava;

error:
	signal__avatar__free_unpacked(ava, alloc);
	return NULL;
}

Signal__Sticker *
signal__sticker__unpack(ProtobufCAllocator *alloc, size_t buflen,
    const uint8_t *buf)
{
	Signal__Sticker		*sti;
	struct tag		 tag;
	size_t			 n;

	sti = malloc(sizeof *sti);
	if (sti == NULL)
		return NULL;

	sti->has_rowid = 0;
	sti->has_length = 0;

	while (buflen > 0) {
		n = tag_unpack(&tag, buflen, buf);
		if (n == 0)
			goto error;

		buf += n;
		buflen -= n;

		switch (tag.fieldnum) {
		case STICKER_ROWID_FIELD:
			if (sti->has_rowid)
				goto error;
			if (tag.wiretype != WIRETYPE_VARINT)
				goto error;

			n = uint64_unpack(&sti->rowid, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;
			sti->has_rowid = 1;
			break;

		case STICKER_LENGTH_FIELD:
			if (sti->has_length)
				goto error;
			if (tag.wiretype != WIRETYPE_VARINT)
				goto error;

			n = uint32_unpack(&sti->length, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;
			sti->has_length = 1;
			break;

		default:
			goto error;
		}
	}

	return sti;

error:
	signal__sticker__free_unpacked(sti, alloc);
	return NULL;
}

Signal__BackupFrame *
signal__backup_frame__unpack(ProtobufCAllocator *alloc, size_t buflen,
    const uint8_t *buf)
{
	Signal__BackupFrame	*frm;
	struct tag		 tag;
	size_t			 fieldlen, n;

	frm = malloc(sizeof *frm);
	if (frm == NULL)
		return NULL;

	frm->header = NULL;
	frm->statement = NULL;
	frm->preference = NULL;
	frm->attachment = NULL;
	frm->version = NULL;
	frm->has_end = 0;
	frm->avatar = NULL;
	frm->sticker = NULL;

	while (buflen > 0) {
		n = tag_unpack(&tag, buflen, buf);
		if (n == 0)
			goto error;

		buf += n;
		buflen -= n;

		switch (tag.fieldnum) {
		case BACKUPFRAME_HEADER_FIELD:
			if (frm->header != NULL)
				goto error;
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			frm->header = signal__header__unpack(alloc, fieldlen,
			    buf);
			if (frm->header == NULL)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;
			break;

		case BACKUPFRAME_STATEMENT_FIELD:
			if (frm->statement != NULL)
				goto error;
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			frm->statement = signal__sql_statement__unpack(alloc,
			    fieldlen, buf);
			if (frm->statement == NULL)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;
			break;

		case BACKUPFRAME_PREFERENCE_FIELD:
			if (frm->preference != NULL)
				goto error;
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			frm->preference = signal__shared_preference__unpack(
			    alloc, fieldlen, buf);
			if (frm->preference == NULL)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;
			break;

		case BACKUPFRAME_ATTACHMENT_FIELD:
			if (frm->attachment != NULL)
				goto error;
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			frm->attachment = signal__attachment__unpack(alloc,
			    fieldlen, buf);
			if (frm->attachment == NULL)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;
			break;

		case BACKUPFRAME_VERSION_FIELD:
			if (frm->version != NULL)
				goto error;
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			frm->version = signal__database_version__unpack(alloc,
			    fieldlen, buf);
			if (frm->version == NULL)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;
			break;

		case BACKUPFRAME_END_FIELD:
			if (frm->has_end)
				goto error;
			if (tag.wiretype != WIRETYPE_VARINT)
				goto error;

			n = bool_unpack(&frm->end, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;
			frm->has_end = 1;
			break;

		case BACKUPFRAME_AVATAR_FIELD:
			if (frm->avatar != NULL)
				goto error;
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			frm->avatar = signal__avatar__unpack(alloc, fieldlen,
			    buf);
			if (frm->avatar == NULL)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;
			break;

		case BACKUPFRAME_STICKER_FIELD:
			if (frm->sticker != NULL)
				goto error;
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			frm->sticker = signal__sticker__unpack(alloc, fieldlen,
			    buf);
			if (frm->sticker == NULL)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;
			break;

		default:
			goto error;

		}
	}

	return frm;

error:
	signal__backup_frame__free_unpacked(frm, alloc);
	return NULL;
}

static void
binarydata_free(ProtobufCBinaryData *bin, __unused ProtobufCAllocator *alloc)
{
	freezero(bin->data, bin->len);
}

void
signal__header__free_unpacked(Signal__Header *hdr, ProtobufCAllocator *alloc)
{
	if (hdr == NULL)
		return;
	if (hdr->has_iv)
		binarydata_free(&hdr->iv, alloc);
	if (hdr->has_salt)
		binarydata_free(&hdr->salt, alloc);
	freezero(hdr, sizeof *hdr);
}

void
signal__sql_statement__sql_parameter__free_unpacked(
    Signal__SqlStatement__SqlParameter *par, ProtobufCAllocator *alloc)
{
	if (par == NULL)
		return;
	freezero_string(par->stringparamter);
	if (par->has_blobparameter)
		binarydata_free(&par->blobparameter, alloc);
	freezero(par, sizeof *par);
}

void
signal__sql_statement__free_unpacked(Signal__SqlStatement *sql,
    ProtobufCAllocator *alloc)
{
	size_t i;

	if (sql == NULL)
		return;
	freezero_string(sql->statement);
	for (i = 0; i < sql->n_parameters; i++)
		signal__sql_statement__sql_parameter__free_unpacked(
		    sql->parameters[i], alloc);
	free(sql->parameters);
	freezero(sql, sizeof *sql);
}

void
signal__shared_preference__free_unpacked(Signal__SharedPreference *prf,
    __unused ProtobufCAllocator *alloc)
{
	if (prf == NULL)
		return;
	freezero_string(prf->file);
	freezero_string(prf->key);
	freezero_string(prf->value);
	freezero(prf, sizeof *prf);
}

void
signal__attachment__free_unpacked(Signal__Attachment *att,
    __unused ProtobufCAllocator *alloc)
{
	if (att == NULL)
		return;
	freezero(att, sizeof *att);
}

void
signal__database_version__free_unpacked(Signal__DatabaseVersion *ver,
    __unused ProtobufCAllocator *alloc)
{
	if (ver == NULL)
		return;
	freezero(ver, sizeof *ver);
}

void
signal__avatar__free_unpacked(Signal__Avatar *avt,
    __unused ProtobufCAllocator *alloc)
{
	if (avt == NULL)
		return;
	freezero_string(avt->name);
	freezero_string(avt->recipientid);
	freezero(avt, sizeof *avt);
}

void
signal__sticker__free_unpacked(Signal__Sticker *stk,
    __unused ProtobufCAllocator *alloc)
{
	if (stk == NULL)
		return;
	freezero(stk, sizeof *stk);
}

void
signal__backup_frame__free_unpacked(Signal__BackupFrame *frm,
    ProtobufCAllocator *alloc)
{
	if (frm == NULL)
		return;
	signal__header__free_unpacked(frm->header, alloc);
	signal__sql_statement__free_unpacked(frm->statement, alloc);
	signal__shared_preference__free_unpacked(frm->preference, alloc);
	signal__attachment__free_unpacked(frm->attachment, alloc);
	signal__database_version__free_unpacked(frm->version, alloc);
	signal__avatar__free_unpacked(frm->avatar, alloc);
	signal__sticker__free_unpacked(frm->sticker, alloc);
	freezero(frm, sizeof *frm);
}

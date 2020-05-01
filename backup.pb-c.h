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

#include <stddef.h>
#include <stdint.h>

typedef struct ProtobufCAllocator	 ProtobufCAllocator;

typedef int				 protobuf_c_boolean;
typedef struct ProtobufCBinaryData	 ProtobufCBinaryData;

typedef struct Signal__Header		 Signal__Header;
typedef struct Signal__SqlStatement__SqlParameter Signal__SqlStatement__SqlParameter;
typedef struct Signal__SqlStatement	 Signal__SqlStatement;
typedef struct Signal__SharedPreference	 Signal__SharedPreference;
typedef struct Signal__Attachment	 Signal__Attachment;
typedef struct Signal__DatabaseVersion	 Signal__DatabaseVersion;
typedef struct Signal__Avatar		 Signal__Avatar;
typedef struct Signal__Sticker		 Signal__Sticker;
typedef struct Signal__BackupFrame	 Signal__BackupFrame;

struct ProtobufCAllocator {
	void				*(*alloc)(void *, size_t);
	void				 (*free)(void *, void *);
	void				*allocator_data;
};

struct ProtobufCBinaryData {
	size_t				 len;
	uint8_t				*data;
};

struct Signal__Header {
	protobuf_c_boolean		 has_iv;
	ProtobufCBinaryData		 iv;
	protobuf_c_boolean		 has_salt;
	ProtobufCBinaryData		 salt;
};

struct Signal__SqlStatement__SqlParameter {
	char				*stringparamter;
	protobuf_c_boolean		 has_integerparameter;
	uint64_t			 integerparameter;
	protobuf_c_boolean		 has_doubleparameter;
	double				 doubleparameter;
	protobuf_c_boolean		 has_blobparameter;
	ProtobufCBinaryData		 blobparameter;
	protobuf_c_boolean		 has_nullparameter;
	protobuf_c_boolean		 nullparameter;
};

struct Signal__SqlStatement {
	char				*statement;
	size_t				 n_parameters;
	Signal__SqlStatement__SqlParameter **parameters;
};

struct Signal__SharedPreference {
	char				*file;
	char				*key;
	char				*value;
};

struct Signal__Attachment {
	protobuf_c_boolean		 has_rowid;
	uint64_t			 rowid;
	protobuf_c_boolean		 has_attachmentid;
	uint64_t			 attachmentid;
	protobuf_c_boolean		 has_length;
	uint32_t			 length;
};

struct Signal__DatabaseVersion {
	protobuf_c_boolean		 has_version;
	uint32_t			 version;
};

struct Signal__Avatar {
	char				*name;
	protobuf_c_boolean		 has_length;
	uint32_t			 length;
	char				*recipientid;
};

struct Signal__Sticker {
	protobuf_c_boolean		 has_rowid;
	uint64_t			 rowid;
	protobuf_c_boolean		 has_length;
	uint32_t			 length;
};

struct Signal__BackupFrame {
	Signal__Header			*header;
	Signal__SqlStatement		*statement;
	Signal__SharedPreference	*preference;
	Signal__Attachment		*attachment;
	Signal__DatabaseVersion		*version;
	protobuf_c_boolean		 has_end;
	protobuf_c_boolean		 end;
	Signal__Avatar			*avatar;
	Signal__Sticker			*sticker;
};

Signal__Header				*signal__header__unpack(ProtobufCAllocator *, size_t, const uint8_t *);
Signal__SqlStatement__SqlParameter	*signal__sql_statement__sql_parameter__unpack(ProtobufCAllocator *, size_t, const uint8_t *);
Signal__SqlStatement			*signal__sql_statement__unpack(ProtobufCAllocator *, size_t, const uint8_t *);
Signal__SharedPreference		*signal__shared_preference__unpack(ProtobufCAllocator *, size_t, const uint8_t *);
Signal__Attachment			*signal__attachment__unpack(ProtobufCAllocator *, size_t, const uint8_t *);
Signal__DatabaseVersion			*signal__database_version__unpack(ProtobufCAllocator *, size_t, const uint8_t *);
Signal__Avatar				*signal__avatar__unpack(ProtobufCAllocator *, size_t, const uint8_t *);
Signal__Sticker				*signal__sticker__unpack(ProtobufCAllocator *, size_t, const uint8_t *);
Signal__BackupFrame			*signal__backup_frame__unpack(ProtobufCAllocator *, size_t, const uint8_t *);

void					 signal__header__free_unpacked(Signal__Header *, ProtobufCAllocator *);
void					 signal__sql_statement__sql_parameter__free_unpacked(Signal__SqlStatement__SqlParameter *, ProtobufCAllocator *);
void					 signal__sql_statement__free_unpacked(Signal__SqlStatement *, ProtobufCAllocator *);
void					 signal__shared_preference__free_unpacked(Signal__SharedPreference *, ProtobufCAllocator *);
void					 signal__attachment__free_unpacked(Signal__Attachment *, ProtobufCAllocator *);
void					 signal__database_version__free_unpacked(Signal__DatabaseVersion *, ProtobufCAllocator *);
void					 signal__avatar__free_unpacked(Signal__Avatar *, ProtobufCAllocator *);
void					 signal__sticker__free_unpacked(Signal__Sticker *, ProtobufCAllocator *);
void					 signal__backup_frame__free_unpacked(Signal__BackupFrame *, ProtobufCAllocator *);

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

#include <errno.h>
#include <stdlib.h>

#include "compat.h"

struct mem_entry {
	void			*ptr;
	size_t			 size;
	RB_ENTRY(mem_entry)	 entries;
};

RB_HEAD(mem_tree, mem_entry);

static int mem_cmp(struct mem_entry *, struct mem_entry *);

static struct mem_tree mem_tree = RB_INITIALIZER(mem_tree);

RB_GENERATE_STATIC(mem_tree, mem_entry, entries, mem_cmp)

static int
mem_cmp(struct mem_entry *e, struct mem_entry *f)
{
	return (e->ptr < f->ptr) ? -1 : (e->ptr > f->ptr);
}

static struct mem_entry *
mem_find(void *ptr)
{
	struct mem_entry e;

	e.ptr = ptr;
	return RB_FIND(mem_tree, &mem_tree, &e);
}

static void *
mem_malloc(size_t size)
{
	struct mem_entry *e;

	if ((e = malloc(sizeof *e)) == NULL)
		return NULL;

	if ((e->ptr = malloc(size)) == NULL) {
		free(e);
		return NULL;
	}

	e->size = size;
	RB_INSERT(mem_tree, &mem_tree, e);
	return e->ptr;
}

static void *
mem_realloc(void *ptr, size_t size)
{
	struct mem_entry *e;

	if (ptr == NULL)
		return mem_malloc(size);

	if ((e = mem_find(ptr)) == NULL) {
		errno = EINVAL;
		return NULL;
	}

	if ((ptr = recallocarray(e->ptr, e->size, size, 1)) == NULL)
		return NULL;

	RB_REMOVE(mem_tree, &mem_tree, e);
	e->ptr = ptr;
	e->size = size;
	RB_INSERT(mem_tree, &mem_tree, e);
	return e->ptr;
}

static void
mem_free(void *ptr)
{
	struct mem_entry *e;

	if (ptr == NULL || (e = mem_find(ptr)) == NULL)
		return;

	RB_REMOVE(mem_tree, &mem_tree, e);
	freezero(e->ptr, e->size);
	free(e);
}

void *
mem_protobuf_malloc(__unused void *data, size_t size)
{
	return mem_malloc(size);
}

void
mem_protobuf_free(__unused void *data, void *ptr)
{
	mem_free(ptr);
}

int
mem_sqlite_init(__unused void *data)
{
	return 0;
}

void
mem_sqlite_shutdown(__unused void *data)
{
}

void *
mem_sqlite_malloc(int size)
{
	if (size < 0) {
		errno = EINVAL;
		return NULL;
	}

	return mem_malloc(size);
}

void *
mem_sqlite_realloc(void *ptr, int size)
{
	if (size < 0) {
		errno = EINVAL;
		return NULL;
	}

	return mem_realloc(ptr, size);
}

void
mem_sqlite_free(void *ptr)
{
	mem_free(ptr);
}

int
mem_sqlite_size(void *ptr)
{
	struct mem_entry *e;

	return ((e = mem_find(ptr)) != NULL) ? e->size : 0;
}

int
mem_sqlite_roundup(int size)
{
	return size;
}

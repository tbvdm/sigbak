/*
 * Copyright (c) 2021 Tim van der Molen <tim@kariliq.nl>
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

#include "database.pb-c.h"

#define FIELDNUM_REACTION_EMOJI			1
#define FIELDNUM_REACTION_AUTHOR		2
#define FIELDNUM_REACTION_SENTTIME		3
#define FIELDNUM_REACTION_RECEIVEDTIME		4

#define FIELDNUM_REACTIONLIST_REACTIONS		1

Signal__ReactionList__Reaction *
signal__reaction_list__reaction__unpack(ProtobufCAllocator *alloc,
    size_t buflen, const uint8_t *buf)
{
	Signal__ReactionList__Reaction *rct;
	struct tag	tag;
	size_t		fieldlen, n;

	rct = malloc(sizeof *rct);
	if (rct == NULL)
		return NULL;

	rct->emoji = NULL;
	rct->author = 0;
	rct->senttime = 0;
	rct->receivedtime = 0;

	while (buflen > 0) {
		n = tag_unpack(&tag, buflen, buf);
		if (n == 0)
			goto error;

		buf += n;
		buflen -= n;

		switch (tag.fieldnum) {
		case FIELDNUM_REACTION_EMOJI:
			if (rct->emoji != NULL)
				goto error;
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			rct->emoji = string_unpack(alloc, fieldlen, buf);
			if (rct->emoji == NULL)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;
			break;

		case FIELDNUM_REACTION_AUTHOR:
			if (tag.wiretype != WIRETYPE_VARINT)
				goto error;

			n = uint64_unpack(&rct->author, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;
			break;

		case FIELDNUM_REACTION_SENTTIME:
			if (tag.wiretype != WIRETYPE_VARINT)
				goto error;

			n = uint64_unpack(&rct->senttime, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;
			break;

		case FIELDNUM_REACTION_RECEIVEDTIME:
			if (tag.wiretype != WIRETYPE_VARINT)
				goto error;

			n = uint64_unpack(&rct->receivedtime, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;
			break;

		default:
			goto error;
		}
	}

	return rct;

error:
	signal__reaction_list__reaction__free_unpacked(rct, alloc);
	return NULL;
}

Signal__ReactionList *
signal__reaction_list__unpack(ProtobufCAllocator *alloc, size_t buflen,
    const uint8_t *buf)
{
	Signal__ReactionList	*lst;
	Signal__ReactionList__Reaction *rct, **newreactions;
	struct tag		 tag;
	size_t			 fieldlen, n;

	lst = malloc(sizeof *lst);
	if (lst == NULL)
		return NULL;

	lst->n_reactions = 0;
	lst->reactions = NULL;

	while (buflen > 0) {
		n = tag_unpack(&tag, buflen, buf);
		if (n == 0)
			goto error;

		buf += n;
		buflen -= n;

		switch (tag.fieldnum) {
		case FIELDNUM_REACTIONLIST_REACTIONS:
			if (tag.wiretype != WIRETYPE_LENGTH_DELIM)
				goto error;

			n = fieldlen_unpack(&fieldlen, buflen, buf);
			if (n == 0)
				goto error;

			buf += n;
			buflen -= n;

			rct = signal__reaction_list__reaction__unpack(alloc,
			    fieldlen, buf);
			if (rct == NULL)
				goto error;

			buf += fieldlen;
			buflen -= fieldlen;

			newreactions = reallocarray(lst->reactions,
			    lst->n_reactions + 1, sizeof *newreactions);
			if (newreactions == NULL) {
				signal__reaction_list__reaction__free_unpacked(
				    rct, alloc);
				goto error;
			}

			newreactions[lst->n_reactions++] = rct;
			lst->reactions = newreactions;
			break;

		default:
			goto error;
		}
	}

	return lst;

error:
	signal__reaction_list__free_unpacked(lst, alloc);
	return NULL;
}

void
signal__reaction_list__reaction__free_unpacked(
    Signal__ReactionList__Reaction *rct, __unused ProtobufCAllocator *alloc)
{
	if (rct == NULL)
		return;
	free(rct->emoji);
	free(rct);
}

void
signal__reaction_list__free_unpacked(Signal__ReactionList *lst,
    ProtobufCAllocator *alloc)
{
	size_t i;

	if (lst == NULL)
		return;
	for (i = 0; i < lst->n_reactions; i++)
		signal__reaction_list__reaction__free_unpacked(
		    lst->reactions[i], alloc);
	free(lst->reactions);
	free(lst);
}

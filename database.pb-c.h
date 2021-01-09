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

#ifndef DATABASE_PB_C_H
#define DATABASE_PB_C_H

#include "protobuf.h"

typedef struct Signal__ReactionList__Reaction Signal__ReactionList__Reaction;
typedef struct Signal__ReactionList Signal__ReactionList;

struct Signal__ReactionList__Reaction {
	char			*emoji;
	uint64_t		 author;
	uint64_t		 senttime;
	uint64_t		 receivedtime;
};

struct Signal__ReactionList {
	size_t			 n_reactions;
	Signal__ReactionList__Reaction **reactions;
};

Signal__ReactionList__Reaction	*signal__reaction_list__reaction__unpack(ProtobufCAllocator *, size_t, const uint8_t *);
Signal__ReactionList		*signal__reaction_list__unpack(ProtobufCAllocator *, size_t, const uint8_t *);

void				 signal__reaction_list__reaction__free_unpacked(Signal__ReactionList__Reaction *, ProtobufCAllocator *);
void				 signal__reaction_list__free_unpacked(Signal__ReactionList *, ProtobufCAllocator *);

#endif

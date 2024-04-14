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

#include "sbk-internal.h"

#define ISEMPTY(s) ((s) == NULL || *(s) == '\0')

const char *
sbk_get_recipient_display_name(const struct sbk_recipient *rcp)
{
	if (rcp != NULL)
		switch (rcp->type) {
		case SBK_CONTACT:
			if (!ISEMPTY(rcp->contact->nickname_joined_name))
				return rcp->contact->nickname_joined_name;
			if (!ISEMPTY(rcp->contact->system_joined_name))
				return rcp->contact->system_joined_name;
			if (!ISEMPTY(rcp->contact->profile_joined_name))
				return rcp->contact->profile_joined_name;
			if (!ISEMPTY(rcp->contact->profile_given_name))
				return rcp->contact->profile_given_name;
			if (!ISEMPTY(rcp->contact->phone))
				return rcp->contact->phone;
			if (!ISEMPTY(rcp->contact->email))
				return rcp->contact->email;
			break;
		case SBK_GROUP:
			if (!ISEMPTY(rcp->group->name))
				return rcp->group->name;
			break;
		}

	return "Unknown";
}

#undef ISEMPTY

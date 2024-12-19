/*
 * Copyright (c) 2024 Roman Zwischelsberger
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

// use a raw string to not loose the line breaks (thanks to https://stackoverflow.com/a/44337236 )
const char *styles_css = R"(
body {
	margin: 0;
	font: 14px/20px Inter, sans-serif;
}
.float_left {
	float: left;
}
.float_right {
	float: right;
	text-align:right;
}
.details {
	color: #70777b;
}

.page_body {
    padding-top: 64px;
    width: 768px;
    margin: 0 auto;
}

.message {
	margin: 0 -10px;
	margin-top: 20px;
	border: 2px white;
	border-radius: 20px;
	background-color: #e9e9e9;
	color: #4b4b4b;
}
.sent {
	margin-left: 100px;
	margin-right: -100px;
	border-color: rgb(51,98,242);
}
.attachment {
	max-width: 748px;
	max-height: 748px;
}


.default {
	padding: 10px;
}
.default .body {
	margin-left: 60px;
}
.default .text {
	word-wrap: break-word;
	line-height: 150%;
	unicode-bidi: plaintext;
	text-align: start;
}
.default .from_name {
    color: #3892db;
    font-weight: 700;
    padding-bottom: 5px;
}

.emoji {
	float: left;
	margin-top: 1px;
}
)";
/*
 * Copyright 2007  Quest Software, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>
#include <stdlib.h>

#include "list.h"

struct item {
    char *str;
    struct item *next, *prev;
};

static struct item *list_head = NULL, *list_tail = NULL;

void list_clear(void) {
    struct item *it;

    /* Walk the list freeing each item */
    it = list_head;
    while (it) {
	struct item *next;

	next = it->next;
	free(it->str);
	free(it);

	it = next;
    }

    list_head = NULL;
    list_tail = NULL;
}

void list_push(const char *msg) {
    struct item *it = calloc(1, sizeof(*it));
    if (!it)
	return;

    it->str = strdup(msg);

    if (!it->str) {
	free(it);
	return;
    }

    if (list_tail) {
	/* Append */
	it->prev = list_tail;
	list_tail->next = it;
	list_tail = it;
    } else {
	/* The only item */
	list_head = it;
	list_tail = it;
    }
}

char *list_pop(void) {
    struct item *this;
    char *str;

    if (!list_tail)
	return NULL;

    this = list_tail;
    list_tail = list_tail->prev;

    if (list_tail) {
	/* At least one item remaining */
	list_tail->next = NULL;
    } else {
	/* No items remaining */
	list_head = list_tail = NULL;
    }

    str = this->str;

    free(this);

    return str;
}

char *list_shift(void) {
    struct item *this;
    char *str;

    if (!list_head)
	return NULL;

    this = list_head;
    list_head = list_head->next;

    if (list_head) {
	/* At least one item remaining */
	list_head->prev = NULL;
    } else {
	/* No items remaining */
	list_head = list_tail = NULL;
    }

    str = this->str;

    free(this);

    return str;
}

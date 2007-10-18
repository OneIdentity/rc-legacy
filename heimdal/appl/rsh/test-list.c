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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "list.h"

void list_clear(void);
void list_push(const char *msg);
char *list_pop(void);
char *list_shift(void);

/**
 * Compares the given strings with strcmp, if they don't match a message is
 * printed showing both and 1 is returned. 0 is returned if they match.
 * Neither pointer may be NULL.
 */
static int compare_words(const char *where, const char *test, const char *expect) {
    assert(where);
    assert(test);
    assert(expect);

    if (strcmp(test, expect) != 0) {
	fprintf(stderr, "%s: Expected [%s], got [%s]\n",
		where, expect, test);
	return 1;
    }
    return 0;
}

static const char *const test_strings[] = {
    "A",
    "B",
    "C"
};

/**
 * Pack all the test strings onto the list.
 */
static void setup(void) {
    size_t i;
    list_clear();

    for (i = 0; i < (sizeof(test_strings) / sizeof(test_strings[0])); ++i)
	list_push(test_strings[i]);
}

/**
 * Returns 1 on failure or 0 on success.
 * Prints a message, too.
 */
static int expect_null(const char *where, const void *ptr) {
    if (ptr != NULL) {
	fprintf(stderr, "%s: Unexpected non-NULL pointer\n", where);
	return 1;
    }
    return 0;
}

int main(void) {
    int failures = 0;
    const size_t num_strs = sizeof(test_strings) / sizeof(test_strings[0]);
    size_t i;

    /* list_pop */
    setup();
    for (i = 0; i < num_strs; ++i) {
	char *item = list_pop();

	failures += compare_words("pop", item, test_strings[num_strs - i - 1]);
	free(item);
    }
    failures += expect_null("pop", list_pop());

    /* list_shift */
    setup();
    for (i = 0; i < num_strs; ++i) {
	char *item = list_shift();

	failures += compare_words("shift", item, test_strings[i]);
	free(item);
    }
    failures += expect_null("shift", list_shift());

    /* Empty queue */
    setup();
    list_clear();
    failures += expect_null("empty", list_shift());

    return !!failures;
}

/* vim: ts=8 sw=4 noet
 */

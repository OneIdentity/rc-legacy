/* 
 * (c) 2007 Quest Software, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *  a. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 
 *  b. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 
 *  c. Neither the name of Quest Software, Inc. nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */ 

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "pgss-common.h"

#if !HAVE_BASENAME
/*
 * Returns the last component of the file path.
 * The return type is not const for historical reasons.
 */
#if !defined(PATH_SEPARATOR)
# define PATH_SEPARATOR '/'
#endif
char *
basename(const char *path)
{
    const char *s, *ret;

    for (s = ret = path; *s; s++)
	if (*s == PATH_SEPARATOR)
	    ret = s + 1;
    return (char *)ret;
}
#endif /* !HAVE_BASENAME */


#if TEST
#include "TEST.h"
void
TEST_basename()
{
    const char *r, *a;;

    a = "";
    r = basename(a);
    TEST_RESULT("case 1", r == a);

    a = "/";
    r = basename(a);
    TEST_RESULT("case 2", r == a + 1);

    a = "/foo";
    r = basename(a);
    TEST_RESULT("case 3", r == a + 1);

    a = "//";
    r = basename(a);
    TEST_RESULT("case 4", r == a + 2);

    a = "//foo";
    r = basename(a);
    TEST_RESULT("case 5", r == a + 2);

    a = "foo";
    r = basename(a);
    TEST_RESULT("case 6", r == a);

    a = "/foo/bar/baz";
    r = basename(a);
    TEST_RESULT("case 7", r == a + 9);
}
#endif /* TEST */

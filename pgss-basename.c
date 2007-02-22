/* (c) 2007 Quest Software, Inc. All rights reserved */

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

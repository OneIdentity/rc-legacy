
#include <stdlib.h>
#if HAVE_LIBGEN_H
# include <libgen.h>
#endif

#if !HAVE_BASENAME
# define basename _pgss_basename
char *basename(const char *);
#endif

#if !HAVE_GETPROGNAME
# define getprogname _pgss_getprogname
const char *getprogname(void);
#endif

#if !HAVE_GETENV
# define getenv(name)	((const char *)0)
#endif

#define lengthof(a)     (sizeof (a)/sizeof (a)[0])
#define new(T)          ((T *)malloc(sizeof (T)))
#define new_array(T,n)  ((T *)malloc((n) * sizeof (T)))
#define xfree(p)	do { if (p) free(p); p = 0; } while (0)

/* Return true if two OIDs are equal. Safe to use with NULL OIDs. */
#define OID_EQUALS(o1, o2) \
        ((o1) == (o2) || \
	      ((o1) && (o2) && (o1)->length == (o2)->length && \
	             memcmp((o1)->elements, (o2)->elements, (o1)->length)))


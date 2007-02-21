
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

#define lengthof(a)     (sizeof (a)/sizeof (a)[0])
#define new(T)          ((T *)malloc(sizeof (T)))


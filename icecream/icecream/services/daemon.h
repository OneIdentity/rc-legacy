
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !HAVE_DAEMON
int daemon (int, int);
#endif

#ifdef __cplusplus
}
#endif

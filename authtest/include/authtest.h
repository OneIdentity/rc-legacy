
/* Colour strings */

extern const char 
    *col_SO, 
    *col_SO_ERR,
    *col_SO_INP,
    *col_SE;

void authtest_init(void);

void debug(const char *fmt, ...);
void debug_nonl(const char *fmt, ...);
void debug_err(const char *fmt, ...);

int strtouid(const char *s);

int privsep_fork(int privsep_uid);
void privsep_exit(int ret);
int privsep_wait(void);

/* Return codes from privsep_fork: */
#define PRIVSEP_PARENT	0
#define PRIVSEP_CHILD	1


#define FLAGS_KIND_REQ 0
#define FLAGS_KIND_RET 1

/* Converts an argument to ISC_REQ_* bits */
ULONG names2flags(const char *names, int kind);

/* Converts ISC_REP_* bits to a string (in static storage) */
const char *flags2str(ULONG flag, int kind);

/* Returns a list of all flags strings */
const char *flags_all(int kind);

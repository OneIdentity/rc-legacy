
/* Converts an argument to ISC_REQ_* bits */
ULONG names2flag(const char *names);

/* Converts ISC_REP_* bits to a string (in static storage) */
const char *flags2str(ULONG flag);

const char *flags_all(void);

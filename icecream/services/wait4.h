
#ifdef __cplusplus
extern "C" {
#endif

#if !HAVE_WAIT4
pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage);
#endif

#ifdef __cplusplus
}
#endif

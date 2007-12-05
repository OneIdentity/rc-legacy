
#ifdef __cplusplus
extern "C" {
#endif

#if !HAVE_SETENV
int setenv(const char *name, const char *value, int overwrite);
#endif

#ifdef __cplusplus
}
#endif

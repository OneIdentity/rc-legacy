
#ifdef __cplusplus
extern "C" {
#endif

#if !HAVE_GETLOADAVG
int getloadavg(double loadavg[], int nelem);
#endif

#ifdef __cplusplus
}
#endif

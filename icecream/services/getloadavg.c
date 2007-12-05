
/* From: http://www-h.eng.cam.ac.uk/help/tpl/unix/HP/bsd_to_hpux.html */

/*
 * getloadavg (ave, n)
 *
 * This routine returns 'n' double precision floats containing
 * the load averages in 'ave'; at most 3 values will be returned.
 *
 * Return value: 0 if successful, -1 if failed (and all load
 * averages are returned as 0).
 */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif

#if !HAVE_GETLOADAVG
/*
 * getloadavg (ave, n)
 *
 * This routine returns 'n' double precision floats containing
 * the load averages in 'ave'; at most 3 values will be returned.
 *
 * Return value: 0 if successful, -1 if failed (and all load
 * averages are returned as 0).
 */

#include <sys/types.h>
#include <stdio.h>
#include <nlist.h>
#include <errno.h>

extern int errno;

#define STRSIZ	512			/* Sprintf buffer size */
static char errstr[STRSIZ];		/* Global sprintf buffer */

int ugetloads(float *a);
static void mperror(const char *s);
static const char *syserr(void);

#define merror(a1)		fprintf(stderr,"%s",a1)
#define merror1(fmt,a1)		{ sprintf(errstr,fmt,a1); merror(errstr); }

struct	nlist nl[] = {
#ifdef stardent
# define unixpath "/unix"
	{ "avenrun" },
#else
#if defined(hpux) || defined(__hpux) || defined(__hpux__)
# define unixpath "/hp-ux"
#ifdef __hppa       /* series 700 & 800 */
	{ "avenrun" },
#else               /* series 300 & 400 */
	{ "_avenrun" },
#endif
#else
# define unixpath "/vmunix"
	{ "_avenrun" },
#endif
#endif
	{ 0 },
};

#ifndef RISCos
	int
getloadavg (double *a, int na)
{
	int i, nreturn;
	static int kmem = -1;
#if defined(vax) || defined(hpux) || defined(__hpux) || defined(__hpux__)
	double avenrun[3];
#else
	long avenrun[3];
#endif
#ifdef NOKMEM
	float aves[3];
#endif /* NOKMEM */

	nreturn = na;
	if ( nreturn < 0 )
		nreturn = 0;
	if ( nreturn > 3 )
		nreturn = 3;

#ifdef NOKMEM
/* Use 'uptime' output for BSD-like systems with no /dev/kmem */

	i = ugetloads(aves);
	if( i == -1 ){
		merror("ugetloads failed\n");
		goto failed;
	}
	for (i = 0; i < nreturn; i++)
		a[i] = aves[i];

#else /*NOKMEM*/

	if(kmem == -1) {
#ifdef sgi
# include <sys/sysmp.h>
	nl[0].n_value = sysmp(MP_KERNADDR, MPKA_AVENRUN) & 0x7fffffff;
#else
		nlist(unixpath, nl);
		if (nl[0].n_type==0) {
			merror1("%s: No namelist\n", unixpath);
			goto failed;
		}
#ifdef stardent
		nl[0].n_value &= 0x7fffffff;
#endif
#endif
		if((kmem = open("/dev/kmem", 0)) == -1) {
			mperror("Can't open(/dev/kmem)");
			goto failed;
		}
	}
	if( lseek(kmem, (off_t)nl[0].n_value, 0) == -1 ){
		mperror("Can't lseek in kmem");
		goto failed;
	}
	if( read(kmem, (char *)avenrun, sizeof(avenrun)) != sizeof(avenrun) ){
		mperror("Can't read kmem");
		goto failed;
	}
	for (i = 0; i < nreturn; i++)
#if defined(sun) || defined(sequent)
		a[i] = avenrun[i] / FSCALE;
#else
#ifdef sgi
		a[i] = avenrun[i] / 1024;
#else
#if defined(BSD4_2) || defined(hpux) || defined(__hpux) || defined(__hpux__)
		a[i] = avenrun[i];
#else
#ifdef stardent
		a[i] = (double)avenrun[i] / (1<<16);
#else
		a[i] = avenrun[i] / 1024;
#endif /*stardent*/
#endif /*BSD4_2*/
#endif /*sgi*/
#endif /*sun*/
#endif /*NOKMEM*/
	return(0);
failed:;
	for (i = 0; i < nreturn; i++)
		a[i] = 0;
	return(-1);
}
#else /*RISCos*/
#include <sys/fixpoint.h>
	static
getloadavg (double *a, int na)
{
	int i, nreturn;
	static int kmem = -1;
	fix avenrun[3];

	nreturn = na;
	if ( nreturn < 0 )
		nreturn = 0;
	if ( nreturn > 3 )
		nreturn = 3;

	if(kmem == -1) {
		nlist("/unix", nl);
		if (nl[0].n_type==0) {
			merror("/unix: No namelist\n");
			goto failed;
		}
		if((kmem = open("/dev/kmem", 0)) == -1) {
			mperror("Can't open(/dev/kmem)");
			goto failed;
		}
	}
	if( lseek(kmem, (off_t)nl[0].n_value, 0) == -1 ){
		mperror("Can't lseek in kmem");
		goto failed;
	}
	if( read(kmem, (char *)avenrun, sizeof(avenrun)) != sizeof(avenrun) ){
		mperror("Can't read kmem");
		goto failed;
	}
	for (i = 0; i < nreturn; i++)
	        a[i] = (int) FIX_TO_INT(avenrun[i]) + .5;
	return(0);
failed:;
	for (i = 0; i < nreturn; i++)
		a[i] = 0;
	return(-1);
}
#endif /* RISCOS */

/* ugetloads(ls)
 * float ld[3];
 *
 * Puts the 1, 5, and 15 minute load averages in the float
 * array passed to it.  This program calls upon uptime(1)
 * which could have different ways of printing ie. with bsd4.2
 * "   9:34pm  up 11 hrs,  3 users,  load average: 0.25, 0.22, 0.24  "
 *                                notice the commas -- ^ --- ^.
 * while bsd4.1 does not print commas.  The BSD41 define will
 * take care of this if that is your system, it defaults to
 * the 4.2 version.
 *
 * Author:
 *  John Bien
 *  {ihnp4 | ucbvax | decvax}!trwrb!jsb
 *
 * This routine taken from comp.sources.unix: Volume 4, Issue 78
 */


int
ugetloads(ld)
float ld[3];
{
    FILE *stream;
    int i;

    if((stream = popen("uptime","r")) == NULL)
	return(-1);

#ifdef BSD41
    i = fscanf(stream,"%*[^l] load average: %f %f %f", &ld[0],&ld[1],&ld[2]);
#else
    i = fscanf(stream,"%*[^l] load average: %f, %f, %f", &ld[0],&ld[1],&ld[2]);
#endif /* BSD41 */
    pclose(stream);
    return i == 3 ? 0 : -1;
}

/* Routine to print messages to stderr, appending the system error message */

static void
mperror(const char *s)
{
	char *p;
	char str[STRSIZ];	/* must have own internal buffer */

	if( (p=index(s,'\n')) != NULL )
		*p = '\0';
	sprintf(str,"%s: %s\n", s, syserr());
	if( p )
		*p = '\n';
	merror(str);
}

/* Routine to get the last system error message */

extern int sys_nerr;
extern char *sys_errlist[];

static const char *
syserr()
{
#if HAVE_STRERROR
	return strerror(errno);
#else
	static char buf[80];

	if (errno >= 0 && errno < sys_nerr)
		return(sys_errlist[errno]);
	sprintf(buf,"Unknown error %d", errno);
	return(buf);
#endif
}

#endif /* !HAVE_GETLOADAVG */

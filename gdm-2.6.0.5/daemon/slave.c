/* GDM - The Gnome Display Manager
 * Copyright (C) 1998, 1999, 2000 Martin K. Petersen <mkp@mkp.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/* This is the gdm slave process. gdmslave runs the chooser, greeter
 * and the user's session scripts. */

#include <config.h>
#include <libgnome/libgnome.h>
#include <gtk/gtkmessagedialog.h>
#include <gdk/gdkx.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <utime.h>
#if defined(_POSIX_PRIORITY_SCHEDULING) && defined(HAVE_SCHED_YIELD)
#include <sched.h>
#endif
#ifdef HAVE_LOGINCAP
#include <login_cap.h>
#endif
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <strings.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <X11/Xlib.h>
#include <X11/Xatom.h>
#ifdef HAVE_XFREE_XINERAMA
#include <X11/extensions/Xinerama.h>
#elif HAVE_SOLARIS_XINERAMA
#include <X11/extensions/xinerama.h>
#endif

#if defined(CAN_USE_SETPENV) && defined(HAVE_USERSEC_H)
#include <usersec.h>
#endif

#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#include <selinux/get_context_list.h>
#endif /* HAVE_SELINUX */

#include <vicious.h>

#include "gdm.h"
#include "slave.h"
#include "misc.h"
#include "verify.h"
#include "filecheck.h"
#include "auth.h"
#include "server.h"
#include "choose.h"
#include "getvt.h"
#include "errorgui.h"
#include "cookie.h"

/* Some per slave globals */
static GdmDisplay *d;
static gchar *login = NULL;
static gboolean greet = FALSE;
static gboolean configurator = FALSE;
static gboolean remanage_asap = FALSE;
static gboolean got_xfsz_signal = FALSE;
static gboolean do_timed_login = FALSE; /* if this is true,
					   login the timed login */
static gboolean do_configurator = FALSE; /* if this is true, login as root
					  * and start the configurator */
static gboolean do_restart_greeter = FALSE; /* if this is true, whack the
					       greeter and try again */
static gboolean restart_greeter_now = FALSE; /* restart_greeter_when the
						SIGCHLD hits */
static gboolean gdm_wait_for_ack = TRUE; /* wait for ack on all messages to
				      * the daemon */
static int in_session_stop = 0;
static int in_usr2_signal = 0;
static gboolean need_to_quit_after_session_stop = FALSE;
static int exit_code_to_use = DISPLAY_REMANAGE;
static gboolean session_started = FALSE;
static gboolean greeter_disabled = FALSE;
static gboolean greeter_no_focus = FALSE;

static uid_t logged_in_uid = -1;
static gid_t logged_in_gid = -1;

static gboolean interrupted = FALSE;
static gchar *ParsedAutomaticLogin = NULL;
static gchar *ParsedTimedLogin = NULL;

static int greeter_fd_out = -1;
static int greeter_fd_in = -1;

typedef struct {
	pid_t pid;
} GdmWaitPid;

static int slave_waitpid_r = -1;
static int slave_waitpid_w = -1;
static GSList *slave_waitpids = NULL;

extern gboolean gdm_first_login;
extern gboolean gdm_emergency_server;
extern pid_t extra_process;
extern int extra_status;
extern int gdm_in_signal;
extern int gdm_normal_runlevel;

extern int slave_fifo_pipe_fd; /* the slavepipe (like fifo) connection, this is the write end */

/* wait for a GO in the SOP protocol */
extern gboolean gdm_wait_for_go;

/* Configuration option variables */
extern gchar *GdmUser;
extern uid_t GdmUserId;
extern gid_t GdmGroupId;
extern gchar *GdmSessDir;
extern gchar *GdmXsession;
extern gchar *GdmDefaultSession;
extern gchar *GdmAutomaticLogin;
extern gboolean GdmAllowRemoteAutoLogin;
extern gboolean GdmAlwaysRestartServer;
extern gboolean GdmAddGtkModules;
extern gboolean GdmDoubleLoginWarning;
extern gchar *GdmConfigurator;
extern gboolean GdmConfigAvailable;
extern gboolean GdmChooserButton;
extern gboolean GdmSystemMenu;
extern gint GdmXineramaScreen;
extern gchar *GdmGreeter;
extern gchar *GdmRemoteGreeter;
extern gchar *GdmGtkModulesList;
extern gchar *GdmChooser;
extern gchar *GdmDisplayInit;
extern gchar *GdmPostLogin;
extern gchar *GdmPreSession;
extern gchar *GdmPostSession;
extern gchar *GdmSuspend;
extern gchar *GdmDefaultPath;
extern gchar *GdmRootPath;
extern gchar *GdmUserAuthFile;
extern gchar *GdmServAuthDir;
extern gchar *GdmDefaultLocale;
extern gchar *GdmTimedLogin;
extern gint GdmTimedLoginDelay;
extern gint GdmUserMaxFile;
extern gint GdmRelaxPerms;
extern gboolean GdmKillInitClients;
extern gint GdmPingInterval;
extern gint GdmRetryDelay;
extern gboolean GdmAllowRoot;
extern gboolean GdmAllowRemoteRoot;
extern gchar *GdmGlobalFaceDir;
extern gboolean GdmDebug;
extern gboolean GdmDisallowTCP;
extern gchar *GdmSoundProgram;
extern gchar *GdmSoundOnLoginFile;


/* Local prototypes */
static gint     gdm_slave_xerror_handler (Display *disp, XErrorEvent *evt);
static gint     gdm_slave_xioerror_handler (Display *disp);
static void	gdm_slave_run (GdmDisplay *display);
static void	gdm_slave_wait_for_login (void);
static void     gdm_slave_greeter (void);
static void     gdm_slave_chooser (void);
static void     gdm_slave_session_start (void);
static void     gdm_slave_session_stop (gboolean run_post_session,
					gboolean no_shutdown_check);
static void     gdm_slave_alrm_handler (int sig);
static void     gdm_slave_term_handler (int sig);
static void     gdm_slave_usr2_handler (int sig);
static void     gdm_slave_quick_exit (gint status);
static void     gdm_slave_exit (gint status, const gchar *format, ...) G_GNUC_PRINTF (2, 3);
static void     gdm_child_exit (gint status, const gchar *format, ...) G_GNUC_PRINTF (2, 3);
static gint     gdm_slave_exec_script (GdmDisplay *d, const gchar *dir,
				       const char *login, struct passwd *pwent,
				       gboolean pass_stdout, 
				       gboolean set_parent);
static gchar *  gdm_parse_enriched_login (const gchar *s, GdmDisplay *display);
static void	gdm_slave_handle_usr2_message (void);
static void	gdm_slave_handle_notify (const char *msg);
static void	create_temp_auth_file (void);
static void	set_xnest_parent_stuff (void);
static void	check_notifies_now (void);
static void	restart_the_greeter (void);

/* Yay thread unsafety */
static gboolean x_error_occured = FALSE;
static gboolean gdm_got_ack = FALSE;
static char * gdm_ack_response = NULL;
static GList *unhandled_notifies = NULL;


/* for signals that want to exit */
static Jmp_buf slave_start_jmp;
static gboolean return_to_slave_start_jmp = FALSE;
static gboolean already_in_slave_start_jmp = FALSE;
static char *slave_start_jmp_error_to_print = NULL;
enum {
	JMP_FIRST_RUN = 0,
	JMP_SESSION_STOP_AND_QUIT = 1,
	JMP_JUST_QUIT_QUICKLY = 2
};
#define SIGNAL_EXIT_WITH_JMP(d,how) \
   {											\
	if ((d)->slavepid == getpid () && return_to_slave_start_jmp) {			\
		already_in_slave_start_jmp = TRUE;					\
		Longjmp (slave_start_jmp, how);						\
	} else {									\
		/* evil! how this this happen */					\
		if (slave_start_jmp_error_to_print != NULL)				\
			gdm_error (slave_start_jmp_error_to_print);			\
		gdm_error ("Bad (very very VERY bad!) things happening in signal");	\
		_exit (DISPLAY_REMANAGE);						\
	}										\
   }

/* notify all waitpids, make waitpids check notifies */
static void
slave_waitpid_notify (void)
{
	/* we're in no slave waitpids */
	if (slave_waitpids == NULL)
		return;

	gdm_sigchld_block_push ();

	if (slave_waitpid_w >= 0)
		VE_IGNORE_EINTR (write (slave_waitpid_w, "N", 1));

	gdm_sigchld_block_pop ();
}

/* make sure to wrap this call with sigchld blocks */
static GdmWaitPid *
slave_waitpid_setpid (pid_t pid)
{
	int p[2];
	GdmWaitPid *wp;

	if G_UNLIKELY (pid <= 1)
		return NULL;

	wp = g_new0 (GdmWaitPid, 1);
	wp->pid = pid;

	if (slave_waitpid_r < 0) {
		if G_UNLIKELY (pipe (p) < 0) {
			gdm_error ("slave_waitpid_setpid: cannot create pipe, trying to wing it");
		} else {
			slave_waitpid_r = p[0];
			slave_waitpid_w = p[1];
		}
	}

	slave_waitpids = g_slist_prepend (slave_waitpids, wp);
	return wp;
}

static void
run_session_output (gboolean read_until_eof)
{
	char buf[256];
	int r, written;
	uid_t old;
	gid_t oldg;
	
	old = geteuid ();
	oldg = getegid ();

	/* make sure we can set the gid */
	NEVER_FAILS_seteuid (0);

	/* make sure we are the user when we do this,
	   for purposes of file limits and all that kind of
	   stuff */
	if G_LIKELY (logged_in_gid >= 0) {
		if G_UNLIKELY (setegid (logged_in_gid) != 0) {
			gdm_error (_("Can't set EGID to user GID"));
			NEVER_FAILS_root_set_euid_egid (old, oldg);
			return;
		}
	}

	if G_LIKELY (logged_in_uid >= 0) {
		if G_UNLIKELY (seteuid (logged_in_uid) != 0) {
			gdm_error (_("Can't set EUID to user UID"));
			NEVER_FAILS_root_set_euid_egid (old, oldg);
			return;
		}
	}

	/* the fd is non-blocking */
	for (;;) {
		VE_IGNORE_EINTR (r = read (d->session_output_fd, buf, sizeof(buf)));

		/* EOF */
		if G_UNLIKELY (r == 0) {
			VE_IGNORE_EINTR (close (d->session_output_fd));
			d->session_output_fd = -1;
			VE_IGNORE_EINTR (close (d->xsession_errors_fd));
			d->xsession_errors_fd = -1;
			break;
		}

		/* Nothing to read */
		if (r < 0 && errno == EAGAIN)
			break;

		/* some evil error */
		if G_UNLIKELY (r < 0) {
			gdm_error ("error reading from session output, closing the pipe");
			VE_IGNORE_EINTR (close (d->session_output_fd));
			d->session_output_fd = -1;
			VE_IGNORE_EINTR (close (d->xsession_errors_fd));
			d->xsession_errors_fd = -1;
			break;
		}

		if G_UNLIKELY (d->xsession_errors_bytes >= MAX_XSESSION_ERRORS_BYTES ||
			       got_xfsz_signal)
			continue;

		/* write until we succeed in writing something */
		VE_IGNORE_EINTR (written = write (d->xsession_errors_fd, buf, r));
		if G_UNLIKELY (written < 0 || got_xfsz_signal) {
			/* evil! */
			break;
		}

		/* write until we succeed in writing everything */
		while G_UNLIKELY (written < r) {
			int n;
			VE_IGNORE_EINTR (n = write (d->xsession_errors_fd, &buf[written], r-written));
			if G_UNLIKELY (n < 0 || got_xfsz_signal) {
				/* evil! */
				break;
			}
			written += n;
		}

		d->xsession_errors_bytes += r;

		if G_UNLIKELY (d->xsession_errors_bytes >= MAX_XSESSION_ERRORS_BYTES &&
			       ! got_xfsz_signal) {
			VE_IGNORE_EINTR (write (d->xsession_errors_fd,
					     "\n...Too much output, ignoring rest...\n",
					     strlen ("\n...Too much output, ignoring rest...\n")));
		}

		/* there wasn't more then buf available, so no need to try reading
		 * again, unless we really want to */
		if (r < sizeof (buf) && ! read_until_eof)
			break;
	}

	NEVER_FAILS_root_set_euid_egid (old, oldg);
}

static void
run_chooser_output (void)
{
	char *bf;

	if G_UNLIKELY (d->chooser_output_fd < 0)
		return;

	/* the fd is non-blocking */
	do {
		bf = gdm_fdgets (d->chooser_output_fd);
		if (bf != NULL) {
			g_free (d->chooser_last_line);
			d->chooser_last_line = bf;
		}
	} while (bf != NULL);
}

#define TIME_UNSET_P(tv) ((tv)->tv_sec == 0 && (tv)->tv_usec == 0)

/* Try to touch an authfb auth file every 12 hours.  That way if it's
 * in /tmp it doesn't get whacked by tmpwatch */
#define TRY_TO_TOUCH_TIME (60*60*12)

static struct timeval *
min_time_to_wait (struct timeval *tv)
{
	if (d->authfb) {
		time_t ct = time (NULL);
		time_t sec_to_wait;

		if (d->last_auth_touch + TRY_TO_TOUCH_TIME + 5 <= ct)
			sec_to_wait = 5;
		else
			sec_to_wait = (d->last_auth_touch + TRY_TO_TOUCH_TIME) - ct;

		if (TIME_UNSET_P (tv) ||
		    sec_to_wait < tv->tv_sec)
			tv->tv_sec = sec_to_wait;
	}
	if (TIME_UNSET_P (tv))
		return NULL;
	else
		return tv;
}

static void
try_to_touch_fb_userauth (void)
{
	if (d->authfb && d->userauth != NULL && logged_in_uid >= 0) {
		time_t ct = time (NULL);

		if (d->last_auth_touch + TRY_TO_TOUCH_TIME <= ct) {
			uid_t old;
			gid_t oldg;

			old = geteuid ();
			oldg = getegid ();

			NEVER_FAILS_seteuid (0);

			/* make sure we are the user when we do this,
			   for purposes of file limits and all that kind of
			   stuff */
			if G_LIKELY (logged_in_gid >= 0) {
				if G_UNLIKELY (setegid (logged_in_gid) != 0) {
					gdm_error ("Can't set GID to user GID");
					NEVER_FAILS_root_set_euid_egid (old, oldg);
					return;
				}
			}

			if G_LIKELY (logged_in_uid >= 0) {
				if G_UNLIKELY (seteuid (logged_in_uid) != 0) {
					gdm_error ("Can't set UID to user UID");
					NEVER_FAILS_root_set_euid_egid (old, oldg);
					return;
				}
			}

			/* This will "touch" the file */
			utime (d->userauth, NULL);

			NEVER_FAILS_root_set_euid_egid (old, oldg);

			d->last_auth_touch = ct;
		}
	}
}

/* must call slave_waitpid_setpid before calling this */
static void
slave_waitpid (GdmWaitPid *wp)
{
	if G_UNLIKELY (wp == NULL)
		return;

	gdm_debug ("slave_waitpid: waiting on %d", (int)wp->pid);

	if G_UNLIKELY (slave_waitpid_r < 0) {
		gdm_error ("slave_waitpid: no pipe, trying to wing it");

		/* This is a real stupid fallback for a real stupid case */
		while (wp->pid > 1) {
			struct timeval tv;
			/* Wait 5 seconds. */
			tv.tv_sec = 5;
			tv.tv_usec = 0;
			select (0, NULL, NULL, NULL, min_time_to_wait (&tv));
			/* don't want to use sleep since we're using alarm
			   for pinging */

			/* try to touch an fb auth file */
			try_to_touch_fb_userauth ();

			if (d->session_output_fd >= 0)
				run_session_output (FALSE /* read_until_eof */);
			if (d->chooser_output_fd >= 0)
				run_chooser_output ();
			check_notifies_now ();
		}
		check_notifies_now ();
	} else {
		gboolean read_session_output = TRUE;

		do {
			char buf[1];
			fd_set rfds;
			int ret;
			struct timeval tv;
			int maxfd;

			FD_ZERO (&rfds);
			FD_SET (slave_waitpid_r, &rfds);
			if (read_session_output &&
			    d->session_output_fd >= 0)
				FD_SET (d->session_output_fd, &rfds);
			if (d->chooser_output_fd >= 0)
				FD_SET (d->chooser_output_fd, &rfds);

			/* unset time */
			tv.tv_sec = 0;
			tv.tv_usec = 0;
			maxfd = MAX (slave_waitpid_r, d->session_output_fd);
			maxfd = MAX (maxfd, d->chooser_output_fd);

			ret = select (maxfd + 1, &rfds, NULL, NULL, min_time_to_wait (&tv));

			/* try to touch an fb auth file */
			try_to_touch_fb_userauth ();

			if (ret > 0) {
			       	if (FD_ISSET (slave_waitpid_r, &rfds)) {
					VE_IGNORE_EINTR (read (slave_waitpid_r, buf, 1));
				}
				if (d->session_output_fd >= 0 &&
				    FD_ISSET (d->session_output_fd, &rfds)) {
					run_session_output (FALSE /* read_until_eof */);
				}
				if (d->chooser_output_fd >= 0 &&
				    FD_ISSET (d->chooser_output_fd, &rfds)) {
					run_chooser_output ();
				}
			} else if (errno == EBADF) {
				read_session_output = FALSE;
			}
			check_notifies_now ();
		} while (wp->pid > 1);
		check_notifies_now ();
	}

	gdm_sigchld_block_push ();

	wp->pid = -1;

	slave_waitpids = g_slist_remove (slave_waitpids, wp);
	g_free (wp);

	gdm_sigchld_block_pop ();

	gdm_debug ("slave_waitpid: done_waiting");
}

static void
check_notifies_now (void)
{
	GList *list, *li;

	if (restart_greeter_now &&
	    do_restart_greeter) {
		do_restart_greeter = FALSE;
		restart_the_greeter ();
	}

	while (unhandled_notifies != NULL) {
		gdm_sigusr2_block_push ();
		list = unhandled_notifies;
		unhandled_notifies = NULL;
		gdm_sigusr2_block_pop ();

		for (li = list; li != NULL; li = li->next) {
			char *s = li->data;
			li->data = NULL;

			gdm_slave_handle_notify (s);

			g_free (s);
		}
		g_list_free (list);
	}

	if (restart_greeter_now &&
	    do_restart_greeter) {
		do_restart_greeter = FALSE;
		restart_the_greeter ();
	}
}

static void
gdm_slave_desensitize_config (void)
{
	if (configurator &&
	    d->dsp != NULL) {
		gulong foo = 1;
		Atom atom = XInternAtom (d->dsp,
					 "_GDM_SETUP_INSENSITIVE",
					 False);
		XChangeProperty (d->dsp,
				 DefaultRootWindow (d->dsp),
				 atom,
				 XA_CARDINAL, 32, PropModeReplace,
				 (unsigned char *) &foo, 1);
		XSync (d->dsp, False);
	}

}

static void
gdm_slave_sensitize_config (void)
{
	if (d->dsp != NULL) {
		XDeleteProperty (d->dsp,
				 DefaultRootWindow (d->dsp),
				 XInternAtom (d->dsp,
					      "_GDM_SETUP_INSENSITIVE",
					      False));
		XSync (d->dsp, False);
	}
}

/* ignore handlers */
static int
ignore_xerror_handler (Display *disp, XErrorEvent *evt)
{
	x_error_occured = TRUE;
	return 0;
}

static void
whack_greeter_fds (void)
{
	if (greeter_fd_out > 0)
		VE_IGNORE_EINTR (close (greeter_fd_out));
	greeter_fd_out = -1;
	if (greeter_fd_in > 0)
		VE_IGNORE_EINTR (close (greeter_fd_in));
	greeter_fd_in = -1;
}

static void
term_session_stop_and_quit (void)
{
	gdm_in_signal = 0;
	already_in_slave_start_jmp = TRUE;
	gdm_wait_for_ack = FALSE;
	need_to_quit_after_session_stop = TRUE;

	if (slave_start_jmp_error_to_print != NULL)
		gdm_error (slave_start_jmp_error_to_print);
	slave_start_jmp_error_to_print = NULL;

	/* only if we're not hanging in session stop and getting a
	   TERM signal again */
	if (in_session_stop == 0 && session_started)
		gdm_slave_session_stop (d->logged_in && login != NULL,
					TRUE /* no_shutdown_check */);

	gdm_debug ("term_session_stop_and_quit: Final cleanup");

	/* Well now we're just going to kill
	 * everything including the X server,
	 * so no need doing XCloseDisplay which
	 * may just get us an XIOError */
	d->dsp = NULL;

	gdm_slave_quick_exit (exit_code_to_use);
}

static void
term_quit (void)
{
	gdm_in_signal = 0;
	already_in_slave_start_jmp = TRUE;
	gdm_wait_for_ack = FALSE;
	need_to_quit_after_session_stop = TRUE;

	if (slave_start_jmp_error_to_print != NULL)
		gdm_error (slave_start_jmp_error_to_print);
	slave_start_jmp_error_to_print = NULL;

	gdm_debug ("term_quit: Final cleanup");

	/* Well now we're just going to kill
	 * everything including the X server,
	 * so no need doing XCloseDisplay which
	 * may just get us an XIOError */
	d->dsp = NULL;

	gdm_slave_quick_exit (exit_code_to_use);
}

static gboolean
parent_exists (void)
{
	pid_t ppid = getppid ();
	static gboolean parent_dead = FALSE; /* once dead, always dead */

	if G_UNLIKELY (parent_dead ||
		       ppid <= 1 ||
		       kill (ppid, 0) < 0) {
		parent_dead = TRUE;
		return FALSE;
	}
	return TRUE;
}

#ifdef SIGXFSZ
static void
gdm_slave_xfsz_handler (int signal)
{
	gdm_in_signal++;

	/* in places where we care we can check
	 * and stop writing */
	got_xfsz_signal = TRUE;

	/* whack self ASAP */
	remanage_asap = TRUE;

	gdm_in_signal--;
}
#endif /* SIGXFSZ */

void 
gdm_slave_start (GdmDisplay *display)
{  
	time_t first_time;
	int death_count;
	struct sigaction alrm, term, child, usr2;
#ifdef SIGXFSZ
	struct sigaction xfsz;
#endif /* SIGXFSZ */
	sigset_t mask;

	/* Ignore SIGUSR1/SIGPIPE, and especially ignore it
	   before the Setjmp */
	gdm_signal_ignore (SIGUSR1);
	gdm_signal_ignore (SIGPIPE);

	/* ignore power failures, up to user processes to
	 * handle things correctly */
#ifdef SIGPWR
	gdm_signal_ignore (SIGPWR);
#endif

	/* The signals we wish to listen to */
	sigemptyset (&mask);
	sigaddset (&mask, SIGINT);
	sigaddset (&mask, SIGTERM);
	sigaddset (&mask, SIGCHLD);
	sigaddset (&mask, SIGUSR2);
	sigaddset (&mask, SIGUSR1); /* normally we ignore USR1 */
	if (display->type == TYPE_XDMCP &&
	    GdmPingInterval > 0) {
		sigaddset (&mask, SIGALRM);
	}
	/* must set signal mask before the Setjmp as it will be
	   restored, and we're only interested in catching the above signals */
	sigprocmask (SIG_UNBLOCK, &mask, NULL);


	if G_UNLIKELY (display == NULL) {
		/* saaay ... what? */
		_exit (DISPLAY_REMANAGE);
	}

	gdm_debug ("gdm_slave_start: Starting slave process for %s", display->name);

	switch (Setjmp (slave_start_jmp)) {
	case JMP_FIRST_RUN:
		return_to_slave_start_jmp = TRUE;
		break;
	case JMP_SESSION_STOP_AND_QUIT:
		term_session_stop_and_quit ();
		/* huh? should never get here */
		_exit (DISPLAY_REMANAGE);
	default:
	case JMP_JUST_QUIT_QUICKLY:
		term_quit ();
		/* huh? should never get here */
		_exit (DISPLAY_REMANAGE);
	}

	if (display->type == TYPE_XDMCP &&
	    GdmPingInterval > 0) {
		/* Handle a ALRM signals from our ping alarms */
		alrm.sa_handler = gdm_slave_alrm_handler;
		alrm.sa_flags = SA_RESTART | SA_NODEFER;
		sigemptyset (&alrm.sa_mask);
		sigaddset (&alrm.sa_mask, SIGALRM);

		if G_UNLIKELY (sigaction (SIGALRM, &alrm, NULL) < 0)
			gdm_slave_exit (DISPLAY_ABORT,
					_("%s: Error setting up %s signal handler: %s"),
					"gdm_slave_start", "ALRM", strerror (errno));
	}

	/* Handle a INT/TERM signals from gdm master */
	term.sa_handler = gdm_slave_term_handler;
	term.sa_flags = SA_RESTART;
	sigemptyset (&term.sa_mask);
	sigaddset (&term.sa_mask, SIGTERM);
	sigaddset (&term.sa_mask, SIGINT);

	if G_UNLIKELY ((sigaction (SIGTERM, &term, NULL) < 0) ||
		       (sigaction (SIGINT, &term, NULL) < 0))
		gdm_slave_exit (DISPLAY_ABORT,
				_("%s: Error setting up %s signal handler: %s"),
				"gdm_slave_start", "TERM/INT", strerror (errno));

	/* Child handler. Keeps an eye on greeter/session */
	child.sa_handler = gdm_slave_child_handler;
	child.sa_flags = SA_RESTART|SA_NOCLDSTOP;
	sigemptyset (&child.sa_mask);
	sigaddset (&child.sa_mask, SIGCHLD);

	if G_UNLIKELY (sigaction (SIGCHLD, &child, NULL) < 0) 
		gdm_slave_exit (DISPLAY_ABORT, _("%s: Error setting up %s signal handler: %s"),
				"gdm_slave_start", "CHLD", strerror (errno));

	/* Handle a USR2 which is ack from master that it received a message */
	usr2.sa_handler = gdm_slave_usr2_handler;
	usr2.sa_flags = SA_RESTART;
	sigemptyset (&usr2.sa_mask);
	sigaddset (&usr2.sa_mask, SIGUSR2);

	if G_UNLIKELY (sigaction (SIGUSR2, &usr2, NULL) < 0)
		gdm_slave_exit (DISPLAY_ABORT, _("%s: Error setting up %s signal handler: %s"),
				"gdm_slave_start", "USR2", strerror (errno));

#ifdef SIGXFSZ
	/* handle the filesize signal */
	xfsz.sa_handler = gdm_slave_xfsz_handler;
	xfsz.sa_flags = SA_RESTART;
	sigemptyset (&xfsz.sa_mask);
	sigaddset (&xfsz.sa_mask, SIGXFSZ);

	if G_UNLIKELY (sigaction (SIGXFSZ, &xfsz, NULL) < 0)
		gdm_slave_exit (DISPLAY_ABORT,
				_("%s: Error setting up %s signal handler: %s"),
				"gdm_slave_start", "XFSZ", strerror (errno));
#endif /* SIGXFSZ */

	first_time = time (NULL);
	death_count = 0;

	for (;;) {
		time_t the_time;

		check_notifies_now ();

		gdm_debug ("gdm_slave_start: Loop Thingie");
		gdm_slave_run (display);

		/* remote and flexi only run once */
		if (display->type != TYPE_LOCAL ||
		    ! parent_exists ()) {
			gdm_server_stop (display);
			gdm_slave_send_num (GDM_SOP_XPID, 0);
			gdm_slave_quick_exit (DISPLAY_REMANAGE);
		}

		the_time = time (NULL);

		death_count ++;

		if ((the_time - first_time) <= 0 ||
		    (the_time - first_time) > 60) {
			first_time = the_time;
			death_count = 0;
		} else if G_UNLIKELY (death_count > 6) {
			gdm_slave_quick_exit (DISPLAY_ABORT);
		}

		gdm_debug ("gdm_slave_start: Reinitializing things");

		if (GdmAlwaysRestartServer) {
			/* Whack the server if we want to restart it next time
			 * we run gdm_slave_run */
			gdm_server_stop (display);
			gdm_slave_send_num (GDM_SOP_XPID, 0);
		} else {
			/* OK about to start again so rebake our cookies and reinit
			 * the server */
			if G_UNLIKELY ( ! gdm_auth_secure_display (d)) {
				gdm_slave_quick_exit (DISPLAY_REMANAGE);
			}
			gdm_slave_send_string (GDM_SOP_COOKIE, d->cookie);

			if G_UNLIKELY ( ! gdm_server_reinit (d)) {
				gdm_error ("Error reinitilizing server");
				gdm_slave_quick_exit (DISPLAY_REMANAGE);
			}
		}
	}
	/* very very very evil, should never break, we can't return from
	   here sanely */
	_exit (DISPLAY_ABORT);
}

static gboolean
setup_automatic_session (GdmDisplay *display, const char *name)
{
	char *new_login;
	g_free (login);
	login = g_strdup (name);

	greet = FALSE;
	gdm_debug ("setup_automatic_session: Automatic login: %s", login);

	/* Run the init script. gdmslave suspends until script
	 * has terminated */
	gdm_slave_exec_script (display, GdmDisplayInit, NULL, NULL,
			       FALSE /* pass_stdout */,
			       TRUE /* set_parent */);

	gdm_debug ("setup_automatic_session: DisplayInit script finished");

	new_login = NULL;
	if ( ! gdm_verify_setup_user (display, login,
				      display->name, &new_login))
		return FALSE;

	if (new_login != NULL) {
		g_free (login);
		login = g_strdup (new_login);
	}

	gdm_debug ("setup_automatic_session: Automatic login successful");

	return TRUE;
}

static void 
gdm_screen_init (GdmDisplay *display) 
{
#ifdef HAVE_XFREE_XINERAMA
	int (* old_xerror_handler) (Display *, XErrorEvent *);
	gboolean have_xinerama = FALSE;

	x_error_occured = FALSE;
	old_xerror_handler = XSetErrorHandler (ignore_xerror_handler);

	have_xinerama = XineramaIsActive (display->dsp);

	XSync (display->dsp, False);
	XSetErrorHandler (old_xerror_handler);

	if (x_error_occured)
		have_xinerama = FALSE;

	if (have_xinerama) {
		int screen_num;
		XineramaScreenInfo *xscreens =
			XineramaQueryScreens (display->dsp,
					      &screen_num);


		if G_UNLIKELY (screen_num <= 0)
			gdm_fail ("Xinerama active, but <= 0 screens?");

		if (screen_num <= GdmXineramaScreen)
			GdmXineramaScreen = 0;

		display->screenx = xscreens[GdmXineramaScreen].x_org;
		display->screeny = xscreens[GdmXineramaScreen].y_org;
		display->screenwidth = xscreens[GdmXineramaScreen].width;
		display->screenheight = xscreens[GdmXineramaScreen].height;

		display->lrh_offsetx =
			DisplayWidth (display->dsp,
				      DefaultScreen (display->dsp))
			- (display->screenx + display->screenwidth);
		display->lrh_offsety =
			DisplayHeight (display->dsp,
				       DefaultScreen (display->dsp))
			- (display->screeny + display->screenheight);

		XFree (xscreens);
	} else
#elif HAVE_SOLARIS_XINERAMA
 /* This code from GDK, Copyright (C) 2002 Sun Microsystems */
 	int opcode;
	int firstevent;
	int firsterror;
	int n_monitors = 0;

	gboolean have_xinerama = FALSE;
	have_xinerama = XQueryExtension (display->dsp,
			"XINERAMA",
			&opcode,
			&firstevent,
			&firsterror);

	if (have_xinerama) {
	
		int result;
		XRectangle monitors[MAXFRAMEBUFFERS];
		unsigned char  hints[16];
		
		result = XineramaGetInfo (display->dsp, 0, monitors, hints, &n_monitors);
		/* Yes I know it should be Success but the current implementation 
		 * returns the num of monitor
		 */
		if G_UNLIKELY (result <= 0)
			gdm_fail ("Xinerama active, but <= 0 screens?");

		if (n_monitors <= GdmXineramaScreen)
			GdmXineramaScreen = 0;

		display->screenx = monitors[GdmXineramaScreen].x;
		display->screeny = monitors[GdmXineramaScreen].y;
		display->screenwidth = monitors[GdmXineramaScreen].width;
		display->screenheight = monitors[GdmXineramaScreen].height;

		display->lrh_offsetx =
			DisplayWidth (display->dsp,
				      DefaultScreen (display->dsp))
			- (display->screenx + display->screenwidth);
		display->lrh_offsety =
			DisplayHeight (display->dsp,
				       DefaultScreen (display->dsp))
			- (display->screeny + display->screenheight);

	} else
#endif
	{
		display->screenx = 0;
		display->screeny = 0;
		display->screenwidth = 0; /* we'll use the gdk size */
		display->screenheight = 0;

		display->lrh_offsetx = 0;
		display->lrh_offsety = 0;
	}
}

static void
gdm_slave_whack_greeter (void)
{
	GdmWaitPid *wp;

	gdm_sigchld_block_push ();

	/* do what you do when you quit, this will hang until the
	 * greeter decides to print an STX\n and die, meaning it can do some
	 * last minute cleanup */
	gdm_slave_greeter_ctl_no_ret (GDM_QUIT, "");

	greet = FALSE;

	wp = slave_waitpid_setpid (d->greetpid);
	gdm_sigchld_block_pop ();

	slave_waitpid (wp);

	d->greetpid = 0;

	whack_greeter_fds ();

	gdm_slave_send_num (GDM_SOP_GREETPID, 0);

	gdm_slave_whack_temp_auth_file ();
}

gboolean
gdm_slave_check_user_wants_to_log_in (const char *user)
{
	gboolean loggedin = FALSE;
	int vt = -1;
	int i;
	char **vec;
	char *msg;
	int r;
	char *but[4];

	if ( ! GdmDoubleLoginWarning ||
	    /* always ignore root here, this is mostly a special case
	     * since a root login may not be a real login, such as the
	     config stuff, and people shouldn't log in as root anyway */
	    strcmp (user, gdm_root_user ()) == 0)
		return TRUE;

	gdm_slave_send_string (GDM_SOP_QUERYLOGIN, user);
	if G_LIKELY (ve_string_empty (gdm_ack_response))
	       return TRUE;	
	vec = g_strsplit (gdm_ack_response, ",", -1);
	if (vec == NULL)
		return TRUE;

	for (i = 0; vec[i] != NULL && vec[i+1] != NULL; i += 2) {
		int ii;
		loggedin = TRUE;
		if (d->console && vt < 0 && sscanf (vec[i+1], "%d", &ii) == 1)
			vt = ii;
	}

	g_strfreev (vec);

	if ( ! loggedin)
		return TRUE;

	but[0] = _("Log in anyway");
	if (vt >= 0) {
		msg = _("You are already logged in.  "
			"You can log in anyway, return to your "
			"previous login session, or abort this "
			"login");
		but[1] = _("Return to previous login");
		but[2] = _("Abort login");
		but[3] = NULL;
	} else {
		msg = _("You are already logged in.  "
			"You can log in anyway or abort this "
			"login");
		but[1] = _("Abort login");
		but[2] = NULL;
	}

	if (greet)
		gdm_slave_greeter_ctl_no_ret (GDM_DISABLE, "");

	r = gdm_failsafe_ask_buttons (d, msg, but);

	if (greet)
		gdm_slave_greeter_ctl_no_ret (GDM_ENABLE, "");

	if (r <= 0)
		return TRUE;

	if (vt >= 0) {
		if (r == 2) /* Abort */
			return FALSE;

		/* Must be that r == 1, that is
		   return to previous login */

		if (d->type == TYPE_FLEXI) {
			gdm_slave_whack_greeter ();
			gdm_server_stop (d);
			gdm_slave_send_num (GDM_SOP_XPID, 0);

			/* wait for a few seconds to avoid any vt changing race
			 */
			gdm_sleep_no_signal (1);

			gdm_change_vt (vt);

			/* we are no longer needed so just die.
			   REMANAGE == ABORT here really */
			gdm_slave_quick_exit (DISPLAY_REMANAGE);
		}

		gdm_change_vt (vt);

		/* abort this login attempt */
		return FALSE;
	} else {
		if (r == 1) /* Abort */
			return FALSE;
		else
			return TRUE;
	}
}

static gboolean do_xfailed_on_xio_error = FALSE;

static void 
gdm_slave_run (GdmDisplay *display)
{  
    gint openretries = 0;
    gint maxtries = 0;
    
    d = display;

    gdm_random_tick ();

    if (d->sleep_before_run > 0) {
	    gdm_debug ("gdm_slave_run: Sleeping %d seconds before server start", d->sleep_before_run);
	    gdm_sleep_no_signal (d->sleep_before_run);
	    d->sleep_before_run = 0;

	    check_notifies_now ();
    }

    /* set it before we run the server, it may be that we're using
     * the XOpenDisplay to find out if a server is ready (as with Xnest) */
    d->dsp = NULL;

    /* if this is local display start a server if one doesn't
     * exist */
    if (SERVER_IS_LOCAL (d) &&
	d->servpid <= 0) {
	    if G_UNLIKELY ( ! gdm_server_start (d,
						TRUE /* try_again_if_busy */,
						FALSE /* treat_as_flexi */,
						20 /* min_flexi_disp */,
						5 /* flexi_retries */)) {
		    /* We're really not sure what is going on,
		     * so we throw up our hands and tell the user
		     * that we've given up.  The error is likely something
		     * internal. */
		    gdm_text_message_dialog
			    (C_(N_("I could not start the X\n"
				   "server (your graphical environment)\n"
				   "due to some internal error.\n"
				   "Please contact your system administrator\n"
				   "or check your syslog to diagnose.\n"
				   "In the meantime this display will be\n"
				   "disabled.  Please restart gdm when\n"
				   "the problem is corrected.")));
		    gdm_slave_quick_exit (DISPLAY_ABORT);
	    }
	    gdm_slave_send_num (GDM_SOP_XPID, d->servpid);

	    check_notifies_now ();
    }

    /* We can use d->handled from now on on this display,
     * since the lookup was done in server start */
    
    ve_setenv ("DISPLAY", d->name, TRUE);
    ve_unsetenv ("XAUTHORITY"); /* just in case it's set */

    gdm_auth_set_local_auth (d);

    if (d->handled) {
	    /* Now the display name and hostname is final */
	    if ( ! ve_string_empty (GdmAutomaticLogin)) {
		    g_free (ParsedAutomaticLogin);
		    ParsedAutomaticLogin = gdm_parse_enriched_login (GdmAutomaticLogin,
								     display);
	    }

	    if ( ! ve_string_empty (GdmTimedLogin)) {
		    g_free (ParsedTimedLogin);
		    ParsedTimedLogin = gdm_parse_enriched_login (GdmTimedLogin,
								 display);
	    }
    }
    
    /* X error handlers to avoid the default one (i.e. exit (1)) */
    do_xfailed_on_xio_error = TRUE;
    XSetErrorHandler (gdm_slave_xerror_handler);
    XSetIOErrorHandler (gdm_slave_xioerror_handler);
    
    /* We keep our own (windowless) connection (dsp) open to avoid the
     * X server resetting due to lack of active connections. */

    gdm_debug ("gdm_slave_run: Opening display %s", d->name);

    /* if local then the the server should be ready for openning, so
     * don't try so long before killing it and trying again */
    if (SERVER_IS_LOCAL (d))
	    maxtries = 2;
    else
	    maxtries = 10;
    
    while (d->handled &&
	   openretries < maxtries &&
	   d->dsp == NULL &&
	   ( ! SERVER_IS_LOCAL (d) || d->servpid > 1)) {
	d->dsp = XOpenDisplay (d->name);
	
	if G_UNLIKELY (d->dsp == NULL) {
	    gdm_debug ("gdm_slave_run: Sleeping %d on a retry", 1+openretries*2);
	    gdm_sleep_no_signal (1+openretries*2);
	    openretries++;
	}
    }

    /* Really this will only be useful for the first local server,
       since that's the only time this can really be on */
    while G_UNLIKELY (gdm_wait_for_go) {
	    struct timeval tv;
	    /* Wait 1 second. */
	    tv.tv_sec = 1;
	    tv.tv_usec = 0;
	    select (0, NULL, NULL, NULL, &tv);
	    /* don't want to use sleep since we're using alarm
	       for pinging */
	    check_notifies_now ();
    }

    /* Set the busy cursor */
    if (d->dsp != NULL) {
	    Cursor xcursor = XCreateFontCursor (d->dsp, GDK_WATCH);
	    XDefineCursor (d->dsp,
			   DefaultRootWindow (d->dsp),
			   xcursor);
	    XFreeCursor (d->dsp, xcursor);
	    XSync (d->dsp, False);
    }

    /* Just a race avoiding sleep, probably not necessary though,
     * but doesn't hurt anything */
    if ( ! d->handled)
	    gdm_sleep_no_signal (1);

    if (SERVER_IS_LOCAL (d)) {
	    gdm_slave_send (GDM_SOP_START_NEXT_LOCAL, FALSE);
    }

    check_notifies_now ();

    /* something may have gone wrong, try xfailed, if local (non-flexi),
     * the toplevel loop of death will handle us */ 
    if G_UNLIKELY (d->handled && d->dsp == NULL) {
	    if (d->type == TYPE_LOCAL)
		    gdm_slave_quick_exit (DISPLAY_XFAILED);
	    else
		    gdm_slave_quick_exit (DISPLAY_ABORT);
    }

    /* OK from now on it's really the user whacking us most likely,
     * we have already started up well */
    do_xfailed_on_xio_error = FALSE;

    /* If XDMCP setup pinging */
    if (d->type == TYPE_XDMCP &&
	GdmPingInterval > 0) {
	    alarm (GdmPingInterval);
    }

    /* checkout xinerama */
    if (d->handled)
	    gdm_screen_init (d);

    /* check log stuff for the server, this is done here
     * because it's really a race */
    if (SERVER_IS_LOCAL (d))
	    gdm_server_checklog (d);

    if ( ! d->handled) {
	    /* yay, we now wait for the server to die */
	    while (d->servpid > 0) {
		    pause ();
	    }
	    gdm_slave_quick_exit (DISPLAY_REMANAGE);
    } else if (d->use_chooser) {
	    /* this usually doesn't return */
	    gdm_slave_chooser ();  /* Run the chooser */
	    return;
    } else if (d->type == TYPE_LOCAL &&
	       gdm_first_login &&
	       ! ve_string_empty (ParsedAutomaticLogin) &&
	       strcmp (ParsedAutomaticLogin, gdm_root_user ()) != 0) {
	    gdm_first_login = FALSE;

	    d->logged_in = TRUE;
	    gdm_slave_send_num (GDM_SOP_LOGGED_IN, TRUE);
	    gdm_slave_send_string (GDM_SOP_LOGIN, ParsedAutomaticLogin);

	    if (setup_automatic_session (d, ParsedAutomaticLogin)) {
		    gdm_slave_session_start ();
	    }

	    gdm_slave_send_num (GDM_SOP_LOGGED_IN, FALSE);
	    d->logged_in = FALSE;
	    gdm_slave_send_string (GDM_SOP_LOGIN, "");
	    logged_in_uid = -1;
	    logged_in_gid = -1;

	    gdm_debug ("gdm_slave_run: Automatic login done");
	    
	    if (remanage_asap) {
		    gdm_slave_quick_exit (DISPLAY_REMANAGE);
	    }

	    /* return to gdm_slave_start so that the server
	     * can be reinitted and all that kind of fun stuff. */
	    return;
    }

    if (gdm_first_login)
	    gdm_first_login = FALSE;

    do {
	    check_notifies_now ();

	    if ( ! greet) {
		    gdm_slave_greeter ();  /* Start the greeter */
		    greeter_no_focus = FALSE;
		    greeter_disabled = FALSE;
	    }

	    gdm_slave_wait_for_login (); /* wait for a password */

	    d->logged_in = TRUE;
	    gdm_slave_send_num (GDM_SOP_LOGGED_IN, TRUE);

	    if (do_timed_login) {
		    /* timed out into a timed login */
		    do_timed_login = FALSE;
		    if (setup_automatic_session (d, ParsedTimedLogin)) {
			    gdm_slave_send_string (GDM_SOP_LOGIN,
						   ParsedTimedLogin);
			    gdm_slave_session_start ();
		    }
	    } else {
		    gdm_slave_send_string (GDM_SOP_LOGIN, login);
		    gdm_slave_session_start ();
	    }

	    gdm_slave_send_num (GDM_SOP_LOGGED_IN, FALSE);
	    d->logged_in = FALSE;
	    gdm_slave_send_string (GDM_SOP_LOGIN, "");
	    logged_in_uid = -1;
	    logged_in_gid = -1;

	    if (remanage_asap) {
		    gdm_slave_quick_exit (DISPLAY_REMANAGE);
	    }

	    if (greet) {
		    greeter_no_focus = FALSE;
		    gdm_slave_greeter_ctl_no_ret (GDM_FOCUS, "");
		    greeter_disabled = FALSE;
		    gdm_slave_greeter_ctl_no_ret (GDM_ENABLE, "");
		    gdm_slave_greeter_ctl_no_ret (GDM_RESETOK, "");
	    }
	    /* Note that greet is only true if the above was no 'login',
	     * so no need to reinit the server nor rebake cookies
	     * nor such nonsense */
    } while (greet);

    /* If XDMCP stop pinging */
    if (d->type == TYPE_XDMCP)
	    alarm (0);
}

/* A hack really, this will wait around until the first mapped window
 * with this class and focus it */
static void
focus_first_x_window (const char *class_res_name)
{
	pid_t pid;
	Display *disp;
	int p[2];
	XWindowAttributes attribs = { 0, };

	if G_UNLIKELY (pipe (p) < 0) {
		p[0] = -1;
		p[1] = -1;
	}

	pid = fork ();
	if G_UNLIKELY (pid < 0) {
		if (p[0] != -1)
			VE_IGNORE_EINTR (close (p[0]));
		if (p[1] != -1)
			VE_IGNORE_EINTR (close (p[1]));
		gdm_error (_("%s: cannot fork"), "focus_first_x_window");
		return;
	}
	/* parent */
	if (pid > 0) {
		/* Wait for this subprocess to start-up */
		if (p[0] >= 0) {
			fd_set rfds;
			struct timeval tv;

			VE_IGNORE_EINTR (close (p[1]));

			FD_ZERO(&rfds);
			FD_SET(p[0], &rfds);

			/* Wait up to 2 seconds. */
			tv.tv_sec = 2;
			tv.tv_usec = 0;

			select(p[0]+1, &rfds, NULL, NULL, &tv);

			VE_IGNORE_EINTR (close (p[0]));
		}
		return;
	}

	gdm_unset_signals ();

	closelog ();

	gdm_close_all_descriptors (0 /* from */, p[1] /* except */, -1 /* except2 */);

	/* No error checking here - if it's messed the best response
         * is to ignore & try to continue */
	gdm_open_dev_null (O_RDONLY); /* open stdin - fd 0 */
	gdm_open_dev_null (O_RDWR); /* open stdout - fd 1 */
	gdm_open_dev_null (O_RDWR); /* open stderr - fd 2 */

	openlog ("gdm", LOG_PID, LOG_DAEMON);

	/* just in case it's set */
	ve_unsetenv ("XAUTHORITY");

	gdm_auth_set_local_auth (d);

	disp = XOpenDisplay (d->name);
	if G_UNLIKELY (disp == NULL) {
		gdm_error (_("%s: cannot open display %s"),
			   "focus_first_x_window",
			   d->name);
		_exit (0);
	}

	XSetInputFocus (disp, PointerRoot, RevertToPointerRoot, CurrentTime);

	/* set event mask for events on root window */
	XGetWindowAttributes (disp,
			      DefaultRootWindow (disp),
			      &attribs);
	XSelectInput (disp,
		      DefaultRootWindow (disp),
		      attribs.your_event_mask |
		      SubstructureNotifyMask);

	if G_LIKELY (p[1] >= 0) {
		VE_IGNORE_EINTR (write (p[1], "!", 1));
		VE_IGNORE_EINTR (close (p[1]));
	}

	for (;;) {
		XEvent event = { 0, };
		XClassHint hint = { NULL, NULL };

		XNextEvent (disp, &event);

		if (event.type == MapNotify &&
		    XGetClassHint (disp,
				   event.xmap.window,
				   &hint) &&
		    hint.res_name != NULL &&
		    strcmp (hint.res_name, class_res_name) == 0) {
			Window root_return;
			int x_return, y_return;
			unsigned int width_return = 0, height_return = 0;
			unsigned int border_width_return;
			unsigned int depth_return;

			XGetGeometry (disp, event.xmap.window,
				      &root_return, &x_return,
				      &y_return, &width_return,
				      &height_return, &border_width_return,
				      &depth_return);
			XWarpPointer (disp, None, event.xmap.window,
				      0, 0, 0, 0,
				      width_return / 2,
				      height_return / 2);
			XSync (disp, False);
			XCloseDisplay (disp);

			_exit (0);
		}
	}
}

static void
run_config (GdmDisplay *display, struct passwd *pwent)
{
	pid_t pid;

	/* Set the busy cursor */
	if (d->dsp != NULL) {
		Cursor xcursor = XCreateFontCursor (d->dsp, GDK_WATCH);
		XDefineCursor (d->dsp,
			       DefaultRootWindow (d->dsp),
			       xcursor);
		XFreeCursor (d->dsp, xcursor);
		XSync (d->dsp, False);
	}

	gdm_sigchld_block_push ();
	gdm_sigterm_block_push ();
	pid = d->sesspid = fork ();
	if (pid == 0)
		gdm_unset_signals ();
	gdm_sigterm_block_pop ();
	gdm_sigchld_block_pop ();

	if G_UNLIKELY (pid < 0) {
		/* return left pointer */
		Cursor xcursor;

		/* can't fork, damnit */
		display->sesspid = 0;
	       
		xcursor = XCreateFontCursor (d->dsp, GDK_LEFT_PTR);
		XDefineCursor (d->dsp,
			       DefaultRootWindow (d->dsp),
			       xcursor);
		XFreeCursor (d->dsp, xcursor);
		XSync (d->dsp, False);

		return;
	}

	if (pid == 0) {
		char **argv;
		/* child */

		setsid ();

		gdm_unset_signals ();

		setuid (0);
		setgid (0);
		gdm_desetuid ();

		/* setup environment */
		gdm_restoreenv ();

		/* root here */
		ve_setenv ("XAUTHORITY", GDM_AUTHFILE (display), TRUE);
		ve_setenv ("DISPLAY", display->name, TRUE);
		ve_setenv ("LOGNAME", pwent->pw_name, TRUE);
		ve_setenv ("USER", pwent->pw_name, TRUE);
		ve_setenv ("USERNAME", pwent->pw_name, TRUE);
		ve_setenv ("HOME", pwent->pw_dir, TRUE);
		ve_setenv ("SHELL", pwent->pw_shell, TRUE);
		ve_setenv ("PATH", GdmRootPath, TRUE);
		ve_setenv ("RUNNING_UNDER_GDM", "true", TRUE);
		if ( ! ve_string_empty (display->theme_name))
			ve_setenv ("GDM_GTK_THEME", display->theme_name, TRUE);
		ve_unsetenv ("MAIL");	/* Unset $MAIL for broken shells */

		closelog ();

		gdm_close_all_descriptors (0 /* from */, -1 /* except */, -1 /* except2 */);

		/* No error checking here - if it's messed the best response
		 * is to ignore & try to continue */
		gdm_open_dev_null (O_RDONLY); /* open stdin - fd 0 */
		gdm_open_dev_null (O_RDWR); /* open stdout - fd 1 */
		gdm_open_dev_null (O_RDWR); /* open stderr - fd 2 */

		openlog ("gdm", LOG_PID, LOG_DAEMON);

		VE_IGNORE_EINTR (chdir (pwent->pw_dir));
		if G_UNLIKELY (errno != 0)
			VE_IGNORE_EINTR (chdir ("/"));

		/* exec the configurator */
		argv = ve_split (GdmConfigurator);
		if G_LIKELY (argv != NULL &&
			     argv[0] != NULL &&
			     access (argv[0], X_OK) == 0)
			VE_IGNORE_EINTR (execv (argv[0], argv));

		gdm_error_box (d,
			       GTK_MESSAGE_ERROR,
			       _("Could not execute the configuration "
				 "program.  Make sure it's path is set "
				 "correctly in the configuration file.  "
				 "I will attempt to start it from the "
				 "default location."));

		argv = ve_split
			(EXPANDED_BINDIR
			 "/gdmsetup --disable-sound --disable-crash-dialog");
		if (access (argv[0], X_OK) == 0)
			VE_IGNORE_EINTR (execv (argv[0], argv));

		gdm_error_box (d,
			       GTK_MESSAGE_ERROR,
			       _("Could not execute the configuration "
				 "program.  Make sure it's path is set "
				 "correctly in the configuration file."));

		_exit (0);
	} else {
		GdmWaitPid *wp;
		
		configurator = TRUE;

		gdm_sigchld_block_push ();
		wp = slave_waitpid_setpid (display->sesspid);
		gdm_sigchld_block_pop ();

		slave_waitpid (wp);

		display->sesspid = 0;
		configurator = FALSE;

		/* this will clean up the sensitivity property */
		gdm_slave_sensitize_config ();
	}
}

static void
restart_the_greeter (void)
{
	do_restart_greeter = FALSE;

	gdm_slave_desensitize_config ();

	/* no login */
	g_free (login);
	login = NULL;

	/* Now restart it */
	if (greet) {
		GdmWaitPid *wp;

		gdm_sigchld_block_push ();

		gdm_slave_greeter_ctl_no_ret (GDM_SAVEDIE, "");

		greet = FALSE;

		wp = slave_waitpid_setpid (d->greetpid);

		gdm_sigchld_block_pop ();

		slave_waitpid (wp);

		d->greetpid = 0;

		whack_greeter_fds ();

		gdm_slave_send_num (GDM_SOP_GREETPID, 0);
	}
	gdm_slave_greeter ();

	if (greeter_disabled)
		gdm_slave_greeter_ctl_no_ret (GDM_DISABLE, "");

	if (greeter_no_focus)
		gdm_slave_greeter_ctl_no_ret (GDM_NOFOCUS, "");

	gdm_slave_sensitize_config ();
}

static void
gdm_slave_wait_for_login (void)
{
	g_free (login);
	login = NULL;

	/* Chat with greeter */
	while (login == NULL) {
		/* init to a sane value */
		do_timed_login = FALSE;
		do_configurator = FALSE;

		if G_UNLIKELY (do_restart_greeter) {
			do_restart_greeter = FALSE;
			restart_the_greeter ();
		}

		/* We are NOT interrupted yet */
		interrupted = FALSE;

		check_notifies_now ();

		/* just for paranoia's sake */
		NEVER_FAILS_root_set_euid_egid (0, 0);

		gdm_debug ("gdm_slave_wait_for_login: In loop");
		login = gdm_verify_user (d /* the display */,
					 NULL /* username*/,
					 d->name /* display name */,
					 d->console /* console? (bool) */);
		gdm_debug ("gdm_slave_wait_for_login: end verify for '%s'",
			   ve_sure_string (login));

		/* Complex, make sure to always handle the do_configurator
		 * do_timed_login and do_restart_greeter after any call
		 * to gdm_verify_user */

		if G_UNLIKELY (do_restart_greeter) {
			g_free (login);
			login = NULL;
			do_restart_greeter = FALSE;
			restart_the_greeter ();
			continue;
		}

		check_notifies_now ();

		if G_UNLIKELY (do_configurator) {
			struct passwd *pwent;
			gboolean oldAllowRoot;

			do_configurator = FALSE;
			g_free (login);
			login = NULL;
			/* clear any error */
			gdm_slave_greeter_ctl_no_ret (GDM_ERRBOX, "");
			/* FIXME: what if the root has different 
			   authentication?  This message ought to be changed
			   to be more general, like "you must authenticate as root"
			   or some such */
			gdm_slave_greeter_ctl_no_ret
				(GDM_MSG,
				 _("Enter the root password\n"
				   "to run the configuration."));

			/* we always allow root for this */
			oldAllowRoot = GdmAllowRoot;
			GdmAllowRoot = TRUE;

			pwent = getpwuid (0);
			if G_UNLIKELY (pwent == NULL) {
				/* what? no "root" ?? */
				gdm_slave_greeter_ctl_no_ret (GDM_RESET, "");
				continue;
			}

			gdm_slave_greeter_ctl_no_ret (GDM_SETLOGIN, pwent->pw_name);
			login = gdm_verify_user (d,
						 pwent->pw_name,
						 d->name,
						 d->console);
			GdmAllowRoot = oldAllowRoot;

			/* Clear message */
			gdm_slave_greeter_ctl_no_ret (GDM_MSG, "");

			if G_UNLIKELY (do_restart_greeter) {
				g_free (login);
				login = NULL;
				do_restart_greeter = FALSE;
				restart_the_greeter ();
				continue;
			}

			check_notifies_now ();

			/* the wanker can't remember his password */
			if (login == NULL) {
				gdm_debug ("gdm_slave_wait_for_login: No login/Bad login");
				gdm_slave_greeter_ctl_no_ret (GDM_RESET, "");
				continue;
			}

			/* wipe the login */
			g_free (login);
			login = NULL;

			/* note that this can still fall through to
			 * the timed login if the user doesn't type in the
			 * password fast enough and there is timed login
			 * enabled */
			if (do_timed_login) {
				break;
			}

			/* the user is a wanker */
			if G_UNLIKELY (do_configurator) {
				do_configurator = FALSE;
				gdm_slave_greeter_ctl_no_ret (GDM_RESET, "");
				continue;
			}

			/* okey dokey, we're root */

			/* get the root pwent */
			pwent = getpwuid (0);

			if G_UNLIKELY (pwent == NULL) {
				/* what? no "root" ??, this is not possible
				 * since we logged in, but I'm paranoid */
				gdm_slave_greeter_ctl_no_ret (GDM_RESET, "");
				continue;
			}

			d->logged_in = TRUE;
			logged_in_uid = 0;
			logged_in_gid = 0;
			gdm_slave_send_num (GDM_SOP_LOGGED_IN, TRUE);
			/* Note: nobody really logged in */
			gdm_slave_send_string (GDM_SOP_LOGIN, "");

			/* disable the login screen, we don't want people to
			 * log in in the meantime */
			gdm_slave_greeter_ctl_no_ret (GDM_DISABLE, "");
			greeter_disabled = TRUE;

			/* make the login screen not focusable */
			gdm_slave_greeter_ctl_no_ret (GDM_NOFOCUS, "");
			greeter_no_focus = TRUE;

			check_notifies_now ();
			restart_greeter_now = TRUE;

			gdm_debug ("gdm_slave_wait_for_login: Running GDM Configurator ...");
			run_config (d, pwent);
			gdm_debug ("gdm_slave_wait_for_login: GDM Configurator finished ...");

			restart_greeter_now = FALSE;

			gdm_verify_cleanup (d);

			gdm_slave_send_num (GDM_SOP_LOGGED_IN, FALSE);
			d->logged_in = FALSE;
			logged_in_uid = -1;
			logged_in_gid = -1;

			if (remanage_asap) {
				gdm_slave_quick_exit (DISPLAY_REMANAGE);
			}

			greeter_no_focus = FALSE;
			gdm_slave_greeter_ctl_no_ret (GDM_FOCUS, "");

			greeter_disabled = FALSE;
			gdm_slave_greeter_ctl_no_ret (GDM_ENABLE, "");
			gdm_slave_greeter_ctl_no_ret (GDM_RESETOK, "");
			continue;
		}

		/* the user timed out into a timed login during the
		 * conversation */
		if (do_timed_login) {
			break;
		}

		if (login == NULL) {
			gdm_debug ("gdm_slave_wait_for_login: No login/Bad login");
			gdm_slave_greeter_ctl_no_ret (GDM_RESET, "");
		}
	}

	/* the user timed out into a timed login during the
	 * conversation */
	if (do_timed_login) {
		g_free (login);
		login = NULL;
		/* timed login is automatic, thus no need for greeter,
		 * we'll take default values */
		gdm_slave_whack_greeter();

		gdm_debug ("gdm_slave_wait_for_login: Timed Login");
	}

	gdm_debug ("gdm_slave_wait_for_login: got_login for '%s'",
		   ve_sure_string (login));
}

/* If path starts with a "trusted" directory, don't sanity check things */
/* This is really somewhat "outdated" as we now really want things in
 * the picture dir or in ~/.gnome2/photo */
static gboolean
is_in_trusted_pic_dir (const char *path)
{
	/* our own pixmap dir is trusted */
	if (strncmp (path, EXPANDED_PIXMAPDIR, sizeof (EXPANDED_PIXMAPDIR)) == 0)
		return TRUE;

	return FALSE;
}

/* This is VERY evil! */
static void
run_pictures (void)
{
	char *response;
	int max_write;
	char buf[1024];
	size_t bytes;
	struct passwd *pwent;
	char *picfile;
	char *picdir;
	FILE *fp;
	char *cfgdir;

	response = NULL;
	for (;;) {
		struct stat s;
		char *tmp, *ret;
		int i, r;

		g_free (response);
		response = gdm_slave_greeter_ctl (GDM_NEEDPIC, "");
		if (ve_string_empty (response)) {
			g_free (response);
			return;
		}

		pwent = getpwnam (response);
		if G_UNLIKELY (pwent == NULL) {
			gdm_slave_greeter_ctl_no_ret (GDM_READPIC, "");
			continue;
		}

		picfile = NULL;

		NEVER_FAILS_seteuid (0);
		if G_UNLIKELY (setegid (pwent->pw_gid) != 0 ||
			       seteuid (pwent->pw_uid) != 0) {
			NEVER_FAILS_root_set_euid_egid (0, GdmGroupId);
			gdm_slave_greeter_ctl_no_ret (GDM_READPIC, "");
			continue;
		}

		if G_LIKELY (picfile == NULL) {
			picfile = g_build_filename (pwent->pw_dir, ".face", NULL);
			if (access (picfile, R_OK) != 0) {
				g_free (picfile);
				picfile = NULL;
			} else if G_UNLIKELY ( ! gdm_file_check ("run_pictures", pwent->pw_uid,
								 pwent->pw_dir, ".face", TRUE, TRUE, GdmUserMaxFile,
								 GdmRelaxPerms)) {
				g_free (picfile);

				NEVER_FAILS_root_set_euid_egid (0, GdmGroupId);

				gdm_slave_greeter_ctl_no_ret (GDM_READPIC, "");
				continue;
			}
		}

		if (picfile == NULL) {
			picfile = g_build_filename (pwent->pw_dir, ".face.icon", NULL);
			if (access (picfile, R_OK) != 0) {
				g_free (picfile);
				picfile = NULL;
			} else if G_UNLIKELY ( ! gdm_file_check ("run_pictures", pwent->pw_uid,
								 pwent->pw_dir, ".face.icon", TRUE, TRUE, GdmUserMaxFile,
								 GdmRelaxPerms)) {
				g_free (picfile);

				NEVER_FAILS_root_set_euid_egid (0, GdmGroupId);

				gdm_slave_greeter_ctl_no_ret (GDM_READPIC, "");
				continue;
			}
		}

		if (picfile == NULL) {
			/* Sanity check on ~user/.gnome2/gdm */
			cfgdir = g_build_filename (pwent->pw_dir, ".gnome2", "gdm", NULL);
			if G_LIKELY (gdm_file_check ("run_pictures", pwent->pw_uid,
						     cfgdir, "gdm", TRUE, TRUE, GdmUserMaxFile,
						     GdmRelaxPerms)) {
				VeConfig *cfg;
				char *cfgfile;

				cfgfile = g_build_filename (pwent->pw_dir, ".gnome2", "gdm", NULL);
				cfg = ve_config_new (cfgfile);
				g_free (cfgfile);
				picfile = ve_config_get_string (cfg, "face/picture=");
				ve_config_destroy (cfg);

				/* must exist and be absolute (note that this check
				 * catches empty strings)*/
				/* Note that these days we just set ~/.face */
				if G_UNLIKELY (picfile != NULL &&
					       (picfile[0] != '/' ||
						/* this catches readability by user */
						access (picfile, R_OK) != 0)) {
					g_free (picfile);
					picfile = NULL;
				}

				if (picfile != NULL) {
					char buf[PATH_MAX];
					if (realpath (picfile, buf) == NULL) {
						g_free (picfile);
						picfile = NULL;
					} else {
						g_free (picfile);
						picfile = g_strdup (buf);
					}
				}

				if G_UNLIKELY (picfile != NULL) {
					char *dir;
					char *base;

					/* if in trusted dir, just use it */
					if (is_in_trusted_pic_dir (picfile)) {
						struct stat s;

						if (stat (picfile, &s) != 0 ||
						    ! S_ISREG (s.st_mode)) {
							g_free (picfile);
							picfile = g_strdup ("");
						}
						NEVER_FAILS_root_set_euid_egid (0, GdmGroupId);

						g_free (cfgdir);

						gdm_slave_greeter_ctl_no_ret (GDM_READPIC,
									      picfile);
						g_free (picfile);
						continue;
					}

					/* if not in trusted dir, check it out */
					dir = g_path_get_dirname (picfile);
					base = g_path_get_basename (picfile);

					/* Note that strict permissions checking is done
					 * on this file.  Even if it may not even be owned by the
					 * user.  This setting should ONLY point to pics in trusted
					 * dirs. */
					if (ve_string_empty (dir) ||
					    ve_string_empty (base) ||
					    ! gdm_file_check ("run_pictures", pwent->pw_uid,
							      dir, base, TRUE, TRUE, GdmUserMaxFile,
							      GdmRelaxPerms)) {
						g_free (picfile);
						picfile = NULL;
					}

					g_free (base);
					g_free (dir);
				}
			}
			g_free (cfgdir);
		}

		/* Nothing found yet, try the old location,
		 * and if we don't find anything there we try the global
		 * dir.  So this is NOT JUST A FALLBACK, don't remove
		 * this branch in the future! */
		if (picfile == NULL) {
			picfile = g_build_filename (pwent->pw_dir, ".gnome2", "photo", NULL);
			picdir = g_build_filename (pwent->pw_dir, ".gnome2", NULL);
			if (access (picfile, F_OK) != 0) {
				g_free (picfile);
				picfile = g_build_filename (pwent->pw_dir, ".gnome", "photo", NULL);
				g_free (picdir);
				picdir = g_build_filename (pwent->pw_dir, ".gnome", NULL);
			}
			if (access (picfile, F_OK) != 0) {
				NEVER_FAILS_root_set_euid_egid (0, GdmGroupId);

				/* Try the global face directory */

				g_free (picfile);
				g_free (picdir);
				picfile = g_build_filename (GdmGlobalFaceDir,
							    response, NULL);

				if (access (picfile, R_OK) == 0) {
					gdm_slave_greeter_ctl_no_ret (GDM_READPIC,
								      picfile);
					g_free (picfile);
					continue;
				}

				g_free (picfile);
				picfile = gdm_make_filename (GdmGlobalFaceDir,
							     response, ".png");

				if (access (picfile, R_OK) == 0) {
					gdm_slave_greeter_ctl_no_ret (GDM_READPIC,
								      picfile);
					g_free (picfile);
					continue;
				}

				gdm_slave_greeter_ctl_no_ret (GDM_READPIC, "");
				g_free (picfile);
				continue;
			}

			/* Sanity check on ~user/.gnome[2]/photo */
			if ( ! gdm_file_check ("run_pictures", pwent->pw_uid,
					       picdir, "photo", TRUE, TRUE, GdmUserMaxFile,
					       GdmRelaxPerms)) {
				g_free (picdir);

				NEVER_FAILS_root_set_euid_egid (0, GdmGroupId);

				gdm_slave_greeter_ctl_no_ret (GDM_READPIC, "");
				continue;
			}
			g_free (picdir);
		}

		VE_IGNORE_EINTR (r = stat (picfile, &s));
		if G_UNLIKELY (r < 0 || s.st_size > GdmUserMaxFile) {
			NEVER_FAILS_root_set_euid_egid (0, GdmGroupId);

			gdm_slave_greeter_ctl_no_ret (GDM_READPIC, "");
			continue;
		}

		VE_IGNORE_EINTR (fp = fopen (picfile, "r"));
		g_free (picfile);
		if G_UNLIKELY (fp == NULL) {
			NEVER_FAILS_root_set_euid_egid (0, GdmGroupId);

			gdm_slave_greeter_ctl_no_ret (GDM_READPIC, "");
			continue;
		}

		tmp = g_strdup_printf ("buffer:%d", (int)s.st_size);
		ret = gdm_slave_greeter_ctl (GDM_READPIC, tmp);
		g_free (tmp);

		if G_UNLIKELY (ret == NULL || strcmp (ret, "OK") != 0) {
			VE_IGNORE_EINTR (fclose (fp));
			g_free (ret);

			NEVER_FAILS_root_set_euid_egid (0, GdmGroupId);

			continue;
		}
		g_free (ret);

		gdm_fdprintf (greeter_fd_out, "%c", STX);

#ifdef PIPE_BUF
		max_write = MIN (PIPE_BUF, sizeof (buf));
#else
		/* apparently Hurd doesn't have PIPE_BUF */
		max_write = fpathconf (greeter_fd_out, _PC_PIPE_BUF);
		/* could return -1 if no limit */
		if (max_write > 0)
			max_write = MIN (max_write, sizeof (buf));
		else
			max_write = sizeof (buf);
#endif

		i = 0;
		while (i < s.st_size) {
			int written;

			VE_IGNORE_EINTR (bytes = fread (buf, sizeof (char),
						     max_write, fp));

			if (bytes <= 0)
				break;

			if G_UNLIKELY (i + bytes > s.st_size)
				bytes = s.st_size - i;

			/* write until we succeed in writing something */
			VE_IGNORE_EINTR (written = write (greeter_fd_out, buf, bytes));
			if G_UNLIKELY (written < 0 &&
				       (errno == EPIPE || errno == EBADF)) {
				/* something very, very bad has happened */
				gdm_slave_quick_exit (DISPLAY_REMANAGE);
			}

			if G_UNLIKELY (written < 0)
				written = 0;

			/* write until we succeed in writing everything */
			while (written < bytes) {
				int n;
				VE_IGNORE_EINTR (n = write (greeter_fd_out, &buf[written], bytes-written));
				if G_UNLIKELY (n < 0 &&
					       (errno == EPIPE || errno == EBADF)) {
					/* something very, very bad has happened */
					gdm_slave_quick_exit (DISPLAY_REMANAGE);
				} else if G_LIKELY (n > 0) {
					written += n;
				}
			}

			/* we have written bytes bytes if it likes it or not */
			i += bytes;
		}

		VE_IGNORE_EINTR (fclose (fp));

		/* eek, this "could" happen, so just send some garbage */
		while G_UNLIKELY (i < s.st_size) {
			bytes = MIN (sizeof (buf), s.st_size - i);
			errno = 0;
			bytes = write (greeter_fd_out, buf, bytes);
			if G_UNLIKELY (bytes < 0 && (errno == EPIPE || errno == EBADF)) {
				/* something very, very bad has happened */
				gdm_slave_quick_exit (DISPLAY_REMANAGE);
			}
			if (bytes > 0)
				i += bytes;
		}
			
		gdm_slave_greeter_ctl_no_ret (GDM_READPIC, "done");

		NEVER_FAILS_root_set_euid_egid (0, GdmGroupId);
	}
	g_free (response);
}

/* hakish, copy file (owned by fromuid) to a temp file owned by touid */
static char *
copy_auth_file (uid_t fromuid, uid_t touid, const char *file)
{
	uid_t old = geteuid ();
	gid_t oldg = getegid ();
	char *name;
	int authfd;
	int fromfd;
	int bytes;
	char buf[2048];
	int cnt;

	NEVER_FAILS_seteuid (0);
	NEVER_FAILS_setegid (GdmGroupId);

	if G_UNLIKELY (seteuid (fromuid) != 0) {
		NEVER_FAILS_root_set_euid_egid (old, oldg);
		return NULL;
	}

	if ( ! gdm_auth_file_check ("copy_auth_file", fromuid,
				    file, FALSE /* absentok */, NULL)) {
		NEVER_FAILS_root_set_euid_egid (old, oldg);
		return NULL;
	}

	do {
		errno = 0;
		fromfd = open (file, O_RDONLY
#ifdef O_NOCTTY
				     |O_NOCTTY
#endif
#ifdef O_NOFOLLOW
				     |O_NOFOLLOW
#endif
				    );
	} while G_UNLIKELY (errno == EINTR);

	if G_UNLIKELY (fromfd < 0) {
		NEVER_FAILS_root_set_euid_egid (old, oldg);
		return NULL;
	}

	NEVER_FAILS_root_set_euid_egid (0, 0);

	name = gdm_make_filename (GdmServAuthDir, d->name, ".XnestAuth");

	VE_IGNORE_EINTR (unlink (name));
	VE_IGNORE_EINTR (authfd = open (name, O_EXCL|O_TRUNC|O_WRONLY|O_CREAT, 0600));

	if G_UNLIKELY (authfd < 0) {
		VE_IGNORE_EINTR (close (fromfd));
		NEVER_FAILS_root_set_euid_egid (old, oldg);
		g_free (name);
		return NULL;
	}

	VE_IGNORE_EINTR (fchown (authfd, touid, -1));

	cnt = 0;
	for (;;) {
		int written, n;
		VE_IGNORE_EINTR (bytes = read (fromfd, buf, sizeof (buf)));

		/* EOF */
		if (bytes == 0)
			break;

		if G_UNLIKELY (bytes < 0) {
			/* Error reading */
			gdm_error ("Error reading %s: %s", file, strerror (errno));
			VE_IGNORE_EINTR (close (fromfd));
			VE_IGNORE_EINTR (close (authfd));
			NEVER_FAILS_root_set_euid_egid (old, oldg);
			g_free (name);
			return NULL;
		}

		written = 0;
		do {
			VE_IGNORE_EINTR (n = write (authfd, &buf[written], bytes-written));
			if G_UNLIKELY (n < 0) {
				/* Error writing */
				gdm_error ("Error writing %s: %s", name, strerror (errno));
				VE_IGNORE_EINTR (close (fromfd));
				VE_IGNORE_EINTR (close (authfd));
				NEVER_FAILS_root_set_euid_egid (old, oldg);
				g_free (name);
				return NULL;
			}
			written += n;
		} while (written < bytes);

		cnt = cnt + written;
		/* this should never occur (we check above)
		   but we're paranoid) */
		if G_UNLIKELY (cnt > GdmUserMaxFile)
			return NULL;
	}

	VE_IGNORE_EINTR (close (fromfd));
	VE_IGNORE_EINTR (close (authfd));

	NEVER_FAILS_root_set_euid_egid (old, oldg);

	return name;
}

static void
exec_command (const char *command, const char *extra_arg)
{
	char **argv = ve_split (command);

	if (argv == NULL ||
	    ve_string_empty (argv[0]))
		return;

	if (access (argv[0], X_OK) != 0)
		return;

	if (extra_arg != NULL) {
		char **new_argv;
		int i;
		for (i = 0; argv[i] != NULL; i++)
			;
		new_argv = g_new0 (char *, i+2);
		for (i = 0; argv[i] != NULL; i++)
			new_argv[i] = argv[i];
		new_argv[i++] = (char *)extra_arg;
		new_argv[i++] = NULL;

		argv = new_argv;
	}

	VE_IGNORE_EINTR (execv (argv[0], argv));
}

static void
gdm_slave_greeter (void)
{
    gint pipe1[2], pipe2[2];  
    struct passwd *pwent;
    pid_t pid;
    char *command;
    
    gdm_debug ("gdm_slave_greeter: Running greeter on %s", d->name);
    
    /* Run the init script. gdmslave suspends until script has terminated */
    gdm_slave_exec_script (d, GdmDisplayInit, NULL, NULL,
			   FALSE /* pass_stdout */,
			   TRUE /* set_parent */);

    /* Open a pipe for greeter communications */
    if G_UNLIKELY (pipe (pipe1) < 0)
	gdm_slave_exit (DISPLAY_REMANAGE, _("%s: Can't init pipe to gdmgreeter"),
			"gdm_slave_greeter");
    if G_UNLIKELY (pipe (pipe2) < 0) {
	VE_IGNORE_EINTR (close (pipe1[0]));
	VE_IGNORE_EINTR (close (pipe1[1]));
	gdm_slave_exit (DISPLAY_REMANAGE, _("%s: Can't init pipe to gdmgreeter"),
			"gdm_slave_greeter");
    }

    /* hackish ain't it */
    create_temp_auth_file ();
    
    /* Fork. Parent is gdmslave, child is greeter process. */
    gdm_sigchld_block_push ();
    gdm_sigterm_block_push ();
    greet = TRUE;
    pid = d->greetpid = fork ();
    if (pid == 0)
	    gdm_unset_signals ();
    gdm_sigterm_block_pop ();
    gdm_sigchld_block_pop ();

    switch (pid) {
	
    case 0:
	setsid ();

	gdm_unset_signals ();

	/* Plumbing */
	VE_IGNORE_EINTR (close (pipe1[1]));
	VE_IGNORE_EINTR (close (pipe2[0]));

	VE_IGNORE_EINTR (dup2 (pipe1[0], STDIN_FILENO));
	VE_IGNORE_EINTR (dup2 (pipe2[1], STDOUT_FILENO));

	closelog ();

	gdm_close_all_descriptors (2 /* from */, -1 /* except */, -1 /* except2 */);

	gdm_open_dev_null (O_RDWR); /* open stderr - fd 2 */

	openlog ("gdm", LOG_PID, LOG_DAEMON);
	
	if G_UNLIKELY (setgid (GdmGroupId) < 0) 
	    gdm_child_exit (DISPLAY_ABORT,
			    _("%s: Couldn't set groupid to %d"),
			    "gdm_slave_greeter", GdmGroupId);

	if G_UNLIKELY (initgroups (GdmUser, GdmGroupId) < 0)
            gdm_child_exit (DISPLAY_ABORT,
			    _("%s: initgroups() failed for %s"),
			    "gdm_slave_greeter", GdmUser);
	
	if G_UNLIKELY (setuid (GdmUserId) < 0) 
	    gdm_child_exit (DISPLAY_ABORT,
			    _("%s: Couldn't set userid to %d"),
			    "gdm_slave_greeter", GdmUserId);

	gdm_restoreenv ();
	
	ve_setenv ("XAUTHORITY", GDM_AUTHFILE (d), TRUE);
	ve_setenv ("DISPLAY", d->name, TRUE);

	/* hackish ain't it */
	set_xnest_parent_stuff ();

	ve_setenv ("LOGNAME", GdmUser, TRUE);
	ve_setenv ("USER", GdmUser, TRUE);
	ve_setenv ("USERNAME", GdmUser, TRUE);
	ve_setenv ("GDM_GREETER_PROTOCOL_VERSION",
		      GDM_GREETER_PROTOCOL_VERSION, TRUE);
	ve_setenv ("GDM_VERSION", VERSION, TRUE);
	ve_unsetenv ("MAIL");	/* Unset $MAIL for broken shells */

	pwent = getpwnam (GdmUser);
	if G_LIKELY (pwent != NULL) {
		/* Note that usually this doesn't exist */
		if (pwent->pw_dir != NULL &&
		    g_file_test (pwent->pw_dir, G_FILE_TEST_EXISTS))
			ve_setenv ("HOME", pwent->pw_dir, TRUE);
		else
			ve_setenv ("HOME", ve_sure_string (GdmServAuthDir), TRUE); /* Hack */
		ve_setenv ("SHELL", pwent->pw_shell, TRUE);
	} else {
		ve_setenv ("HOME", ve_sure_string (GdmServAuthDir), TRUE); /* Hack */
		ve_setenv ("SHELL", "/bin/sh", TRUE);
	}
	if (ve_string_empty (g_getenv ("PATH"))) {
		ve_setenv ("PATH", GdmDefaultPath, TRUE);
	} else if ( ! ve_string_empty (GdmDefaultPath)) {
		ve_setenv ("PATH", g_strconcat (g_getenv ("PATH"), ":", GdmDefaultPath, NULL), TRUE);
	}
	ve_setenv ("RUNNING_UNDER_GDM", "true", TRUE);
	if ( ! ve_string_empty (d->theme_name))
		ve_setenv ("GDM_GTK_THEME", d->theme_name, TRUE);

	/* Note that this is just informative, the slave will not listen to
	 * the greeter even if it does something it shouldn't on a non-local
	 * display so it's not a security risk */
	if (d->console) {
		ve_setenv ("GDM_IS_LOCAL", "yes", TRUE);
	} else {
		ve_unsetenv ("GDM_IS_LOCAL");
	}

	/* this is again informal only, if the greeter does time out it will
	 * not actually login a user if it's not enabled for this display */
	if (d->timed_login_ok) {
		if(ParsedTimedLogin == NULL)
			ve_setenv ("GDM_TIMED_LOGIN_OK", " ", TRUE);
		else
			ve_setenv ("GDM_TIMED_LOGIN_OK", ParsedTimedLogin, TRUE);
	} else {
		ve_unsetenv ("GDM_TIMED_LOGIN_OK");
	}

	if (d->type == TYPE_FLEXI) {
		ve_setenv ("GDM_FLEXI_SERVER", "yes", TRUE);
	} else if (d->type == TYPE_FLEXI_XNEST) {
		ve_setenv ("GDM_FLEXI_SERVER", "Xnest", TRUE);
	} else {
		ve_unsetenv ("GDM_FLEXI_SERVER");
	}

	if G_UNLIKELY (gdm_emergency_server) {
		gdm_error_box (d,
			       GTK_MESSAGE_ERROR,
			       _("No servers were defined in the "
				 "configuration file and XDMCP was "
				 "disabled.  This can only be a "
				 "configuration error.  So I have started "
				 "a single server for you.  You should "
				 "log in and fix the configuration.  "
				 "Note that automatic and timed logins "
				 "are disabled now."));
		ve_unsetenv ("GDM_TIMED_LOGIN_OK");
	}

	if G_UNLIKELY (d->failsafe_xserver) {
		gdm_error_box (d,
			       GTK_MESSAGE_ERROR,
			       _("I could not start the regular X "
				 "server (your graphical environment) "
				 "and so this is a failsafe X server.  "
				 "You should log in and properly "
				 "configure the X server."));
	}

	if G_UNLIKELY (d->busy_display) {
		char *msg = g_strdup_printf
			(_("The specified display number was busy, so "
			   "this server was started on display %s."),
			 d->name);
		gdm_error_box (d, GTK_MESSAGE_ERROR, msg);
		g_free (msg);
	}

	if (d->console)
		command = GdmGreeter;
	else
		command = GdmRemoteGreeter;

	if G_UNLIKELY (d->try_different_greeter) {
		/* FIXME: we should also really be able to do standalone failsafe
		   login, but that requires some work and is perhaps an overkill. */
		/* This should handle mostly the case where gdmgreeter is crashing
		   and we'd want to start gdmlogin for the user so that at least
		   something works instead of a flickering screen */
		gdm_error_box (d,
			       GTK_MESSAGE_ERROR,
			       _("The greeter program appears to be crashing.\n"
				 "I will attempt to use a different one."));
		if (strstr (command, "gdmlogin") != NULL) {
			/* in case it is gdmlogin that's crashing
			   try the graphical greeter for luck */
			command = EXPANDED_BINDIR "/gdmgreeter";
		} else {
			/* in all other cases, try the gdmlogin (standard greeter)
			   proggie */
			command = EXPANDED_BINDIR "/gdmlogin";
		}
	}

	if (GdmAddGtkModules &&
	    ! ve_string_empty (GdmGtkModulesList) &&
	    /* don't add modules if we're trying to prevent crashes,
	       perhaps it's the modules causing the problem in the first place */
	    ! d->try_different_greeter) {
		gchar *modules = g_strdup_printf ("--gtk-module=%s", GdmGtkModulesList);
		exec_command (command, modules);
		/* Something went wrong */
		gdm_error (_("%s: Cannot start greeter with gtk modules: %s. Trying without modules"),
			   "gdm_slave_greeter",
			   GdmGtkModulesList);
		g_free (modules);
	}
	exec_command (command, NULL);

	gdm_error (_("%s: Cannot start greeter trying default: %s"),
		   "gdm_slave_greeter",
		   EXPANDED_BINDIR "/gdmlogin");

	ve_setenv ("GDM_WHACKED_GREETER_CONFIG", "true", TRUE);

	exec_command (EXPANDED_BINDIR "/gdmlogin", NULL);

	VE_IGNORE_EINTR (execl (EXPANDED_BINDIR "/gdmlogin", EXPANDED_BINDIR "/gdmlogin", NULL));

	gdm_error_box (d,
		       GTK_MESSAGE_ERROR,
		       _("Cannot start the greeter program, "
			 "you will not be able to log in.  "
			 "This display will be disabled.  "
			 "Try logging in by other means and "
			 "editing the configuration file"));
	
	/* If no greeter we really have to disable the display */
	gdm_child_exit (DISPLAY_ABORT, _("%s: Error starting greeter on display %s"), "gdm_slave_greeter", d->name);
	
    case -1:
	d->greetpid = 0;
	gdm_slave_exit (DISPLAY_REMANAGE, _("%s: Can't fork gdmgreeter process"), "gdm_slave_greeter");
	
    default:
	VE_IGNORE_EINTR (close (pipe1[0]));
	VE_IGNORE_EINTR (close (pipe2[1]));

	whack_greeter_fds ();

	greeter_fd_out = pipe1[1];
	greeter_fd_in = pipe2[0];
	
	gdm_debug ("gdm_slave_greeter: Greeter on pid %d", (int)pid);

	gdm_slave_send_num (GDM_SOP_GREETPID, d->greetpid);

	run_pictures (); /* Append pictures to greeter if browsing is on */

	check_notifies_now ();
	break;
    }
}

/* This should not call anything that could cause a syslog in case we
 * are in a signal */
void
gdm_slave_send (const char *str, gboolean wait_for_ack)
{
	int fd;
	char *fifopath;
	int i;
	uid_t old;

	if ( ! gdm_wait_for_ack)
		wait_for_ack = FALSE;

	/* Evil!, all this for debugging? */
	if G_UNLIKELY (GdmDebug && gdm_in_signal == 0) {
		if (strncmp (str, GDM_SOP_COOKIE " ",
			     strlen (GDM_SOP_COOKIE " ")) == 0) {
			char *s = g_strndup
				(str, strlen (GDM_SOP_COOKIE " XXXX XX"));
			/* cut off most of the cookie for "security" */
			gdm_debug ("Sending %s...", s);
			g_free (s);
		} else {
			gdm_debug ("Sending %s", str);
		}
	}

	if (wait_for_ack) {
		gdm_got_ack = FALSE;
		g_free (gdm_ack_response);
		gdm_ack_response = NULL;
	}

	/* ensure this is sent from the actual slave with the pipe always, this is anal I know */
	if G_LIKELY (d->slavepid == getpid ()) {
		fd = slave_fifo_pipe_fd;
	} else {
		fd = -1;
	}

	if G_UNLIKELY (fd < 0) {
		/* FIXME: This is not likely to ever be used, remove
		   at some point.  Other then slaves shouldn't be using
		   these functions.  And if the pipe creation failed
		   in main daemon just abort the main daemon.  */
		/* Use the fifo as a fallback only now that we have a pipe */
		fifopath = g_build_filename (GdmServAuthDir, ".gdmfifo", NULL);
		old = geteuid ();
		if (old != 0)
			seteuid (0);
#ifdef O_NOFOLLOW
		VE_IGNORE_EINTR (fd = open (fifopath, O_WRONLY|O_NOFOLLOW));
#else
		VE_IGNORE_EINTR (fd = open (fifopath, O_WRONLY));
#endif
		if (old != 0)
			seteuid (old);
		g_free (fifopath);
	}

	/* eek */
	if G_UNLIKELY (fd < 0) {
		if (gdm_in_signal == 0)
			gdm_error (_("%s: Can't open fifo!"), "gdm_slave_send");
		return;
	}

	gdm_fdprintf (fd, "\n%s\n", str);

	if G_UNLIKELY (fd != slave_fifo_pipe_fd) {
		VE_IGNORE_EINTR (close (fd));
	}

#if defined(_POSIX_PRIORITY_SCHEDULING) && defined(HAVE_SCHED_YIELD)
	if (wait_for_ack && ! gdm_got_ack) {
		/* let the other process do its stuff */
		sched_yield ();
	}
#endif

	for (i = 0;
	     wait_for_ack &&
	     ! gdm_got_ack &&
	     parent_exists () &&
	     i < 10;
	     i++) {
		if (in_usr2_signal > 0) {
			fd_set rfds;
			struct timeval tv;

			FD_ZERO (&rfds);
			FD_SET (d->slave_notify_fd, &rfds);

			/* Wait up to 1 second. */
			tv.tv_sec = 1;
			tv.tv_usec = 0;

			if (select (d->slave_notify_fd+1, &rfds, NULL, NULL, &tv) > 0) {
				gdm_slave_handle_usr2_message ();
			}
		} else {
			struct timeval tv;
			/* Wait 1 second. */
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			select (0, NULL, NULL, NULL, &tv);
			/* don't want to use sleep since we're using alarm
			   for pinging */
		}
	}

	if G_UNLIKELY (wait_for_ack  &&
		       ! gdm_got_ack &&
		       gdm_in_signal == 0) {
		if (strncmp (str, GDM_SOP_COOKIE " ",
			     strlen (GDM_SOP_COOKIE " ")) == 0) {
			char *s = g_strndup
				(str, strlen (GDM_SOP_COOKIE " XXXX XX"));
			/* cut off most of the cookie for "security" */
			gdm_debug ("Timeout occured for sending message %s...", s);
			g_free (s);
		} else {
			gdm_debug ("Timeout occured for sending message %s", str);
		}
	}
}

void
gdm_slave_send_num (const char *opcode, long num)
{
	char *msg;

	if (gdm_in_signal == 0)
		gdm_debug ("Sending %s == %ld for slave %ld",
			   opcode,
			   (long)num,
			   (long)getpid ());

	msg = g_strdup_printf ("%s %ld %ld", opcode,
			       (long)getpid (), (long)num);

	gdm_slave_send (msg, TRUE);

	g_free (msg);
}

void
gdm_slave_send_string (const char *opcode, const char *str)
{
	char *msg;

	/* Evil!, all this for debugging? */
	if G_UNLIKELY (GdmDebug && gdm_in_signal == 0) {
		if (strcmp (opcode, GDM_SOP_COOKIE) == 0)
			gdm_debug ("Sending %s == <secret> for slave %ld",
				   opcode,
				   (long)getpid ());
		else
			gdm_debug ("Sending %s == %s for slave %ld",
				   opcode,
				   ve_sure_string (str),
				   (long)getpid ());
	}

	msg = g_strdup_printf ("%s %ld %s", opcode,
			       (long)getpid (), ve_sure_string (str));

	gdm_slave_send (msg, TRUE);

	g_free (msg);
}

static void
send_chosen_host (GdmDisplay *disp, const char *hostname)
{
	GdmHostent *host;
	struct in_addr ia;
#ifdef ENABLE_IPV6
	struct sockaddr_storage ss;
#endif
	char *str = NULL;

	host = gdm_gethostbyname (hostname);

	if G_UNLIKELY (host->addrs == NULL) {
		gdm_error ("Cannot get address of host '%s'", hostname);
		gdm_hostent_free (host);
		return;
	}
	/* take first address */
#ifdef ENABLE_IPV6
	memcpy (&ss, &host->addrs[0], sizeof (struct sockaddr_storage));
	if (ss.ss_family == AF_INET6) {
		struct in6_addr ia6;
		char buffer6[INET6_ADDRSTRLEN];

		memcpy (&ia6, &((struct sockaddr_in6 *)&ss)->sin6_addr, sizeof (struct in6_addr));
		gdm_hostent_free (host);
		gdm_debug ("Sending chosen host address (%s) %s", hostname, inet_ntop (AF_INET6, &ia6, buffer6, sizeof (buffer6)));
		str = g_strdup_printf ("%s %d %s", GDM_SOP_CHOSEN, disp->indirect_id, buffer6);
	}
	else if (ss.ss_family == AF_INET) {
		char buffer[INET_ADDRSTRLEN];

		memcpy (&ia, &((struct sockaddr_in *)&ss)->sin_addr, sizeof (struct in_addr));
		gdm_hostent_free (host);
		gdm_debug ("Sending chosen host address (%s) %s", hostname, inet_ntop (AF_INET, &ia, buffer, sizeof (buffer)));
		str = g_strdup_printf ("%s %d %s", GDM_SOP_CHOSEN, disp->indirect_id, buffer);
	}
#else
	ia = host->addrs[0];
	gdm_hostent_free (host);

	gdm_debug ("Sending chosen host address (%s) %s",
		   hostname, inet_ntoa (ia));

	str = g_strdup_printf ("%s %d %s", GDM_SOP_CHOSEN,
			       disp->indirect_id,
			       inet_ntoa (ia));

#endif
	gdm_slave_send (str, FALSE);

	g_free (str);
}


static void
gdm_slave_chooser (void)
{
	gint p[2];
	struct passwd *pwent;
	pid_t pid;
	GdmWaitPid *wp;

	gdm_debug ("gdm_slave_chooser: Running chooser on %s", d->name);

	/* Open a pipe for chooser communications */
	if G_UNLIKELY (pipe (p) < 0)
		gdm_slave_exit (DISPLAY_REMANAGE, _("%s: Can't init pipe to gdmchooser"), "gdm_slave_chooser");

	/* Run the init script. gdmslave suspends until script has terminated */
	gdm_slave_exec_script (d, GdmDisplayInit, NULL, NULL,
			       FALSE /* pass_stdout */,
			       TRUE /* set_parent */);

	/* Fork. Parent is gdmslave, child is greeter process. */
	gdm_sigchld_block_push ();
	gdm_sigterm_block_push ();
	pid = d->chooserpid = fork ();
	if (pid == 0)
		gdm_unset_signals ();
	gdm_sigterm_block_pop ();
	gdm_sigchld_block_pop ();

	switch (pid) {

	case 0:
		setsid ();

		gdm_unset_signals ();

		/* Plumbing */
		VE_IGNORE_EINTR (close (p[0]));

		if (p[1] != STDOUT_FILENO) 
			VE_IGNORE_EINTR (dup2 (p[1], STDOUT_FILENO));

		closelog ();

		VE_IGNORE_EINTR (close (0));
		gdm_close_all_descriptors (2 /* from */, -1 /* except */, -1 /* except2 */);

		gdm_open_dev_null (O_RDONLY); /* open stdin - fd 0 */
		gdm_open_dev_null (O_RDWR); /* open stderr - fd 2 */

		openlog ("gdm", LOG_PID, LOG_DAEMON);

		if G_UNLIKELY (setgid (GdmGroupId) < 0) 
			gdm_child_exit (DISPLAY_ABORT,
					_("%s: Couldn't set groupid to %d"),
					"gdm_slave_chooser", GdmGroupId);

		if G_UNLIKELY (initgroups (GdmUser, GdmGroupId) < 0)
			gdm_child_exit (DISPLAY_ABORT,
					_("%s: initgroups() failed for %s"),
					"gdm_slave_chooser", GdmUser);

		if G_UNLIKELY (setuid (GdmUserId) < 0) 
			gdm_child_exit (DISPLAY_ABORT,
					_("%s: Couldn't set userid to %d"),
					"gdm_slave_chooser", GdmUserId);

		gdm_restoreenv ();

		ve_setenv ("XAUTHORITY", GDM_AUTHFILE (d), TRUE);
		ve_setenv ("DISPLAY", d->name, TRUE);

		ve_setenv ("LOGNAME", GdmUser, TRUE);
		ve_setenv ("USER", GdmUser, TRUE);
		ve_setenv ("USERNAME", GdmUser, TRUE);

		ve_setenv ("GDM_VERSION", VERSION, TRUE);

		ve_unsetenv ("MAIL");	/* Unset $MAIL for broken shells */

		pwent = getpwnam (GdmUser);
		if G_LIKELY (pwent != NULL) {
			/* Note that usually this doesn't exist */
			if (g_file_test (pwent->pw_dir, G_FILE_TEST_EXISTS))
				ve_setenv ("HOME", pwent->pw_dir, TRUE);
			else
				ve_setenv ("HOME", ve_sure_string (GdmServAuthDir), TRUE); /* Hack */
			ve_setenv ("SHELL", pwent->pw_shell, TRUE);
		} else {
			ve_setenv ("HOME", ve_sure_string (GdmServAuthDir), TRUE); /* Hack */
			ve_setenv ("SHELL", "/bin/sh", TRUE);
		}
		if (ve_string_empty (g_getenv ("PATH"))) {
			ve_setenv ("PATH", GdmDefaultPath, TRUE);
		} else if ( ! ve_string_empty (GdmDefaultPath)) {
			ve_setenv ("PATH", g_strconcat (g_getenv ("PATH"), ":", GdmDefaultPath, NULL), TRUE);
		}
		ve_setenv ("RUNNING_UNDER_GDM", "true", TRUE);
		if ( ! ve_string_empty (d->theme_name))
			ve_setenv ("GDM_GTK_THEME", d->theme_name, TRUE);

		if (GdmAddGtkModules &&
		    ! ve_string_empty (GdmGtkModulesList)) {
			char *modules = g_strdup_printf ("--gtk-module=%s", GdmGtkModulesList);
			exec_command (GdmChooser, modules);
		}

		exec_command (GdmChooser, NULL);

		gdm_error_box (d,
			       GTK_MESSAGE_ERROR,
			       _("Cannot start the chooser program, "
				 "you will probably not be able to log in.  "
				 "Please contact the system administrator."));

		gdm_child_exit (DISPLAY_REMANAGE, _("%s: Error starting chooser on display %s"), "gdm_slave_chooser", d->name);

	case -1:
		gdm_slave_exit (DISPLAY_REMANAGE, _("%s: Can't fork gdmchooser process"), "gdm_slave_chooser");

	default:
		gdm_debug ("gdm_slave_chooser: Chooser on pid %d", d->chooserpid);
		gdm_slave_send_num (GDM_SOP_CHOOSERPID, d->chooserpid);

		VE_IGNORE_EINTR (close (p[1]));

		g_free (d->chooser_last_line);
		d->chooser_last_line = NULL;
		d->chooser_output_fd = p[0];
		/* make the output read fd non-blocking */
		fcntl (d->chooser_output_fd, F_SETFL, O_NONBLOCK);

		/* wait for the chooser to die */

		gdm_sigchld_block_push ();
		wp = slave_waitpid_setpid (d->chooserpid);
		gdm_sigchld_block_pop ();

		slave_waitpid (wp);

		d->chooserpid = 0;
		gdm_slave_send_num (GDM_SOP_CHOOSERPID, 0);

		/* Note: Nothing affecting the chooser needs update
		 * from notifies, plus we are exitting right now */

		run_chooser_output ();
		VE_IGNORE_EINTR (close (d->chooser_output_fd));
		d->chooser_output_fd = -1;

		if (d->chooser_last_line != NULL) {
			char *host = d->chooser_last_line;
			d->chooser_last_line = NULL;

			if (d->type == TYPE_XDMCP) {
				send_chosen_host (d, host);
				gdm_slave_quick_exit (DISPLAY_CHOSEN);
			} else {
				gdm_debug ("Sending locally chosen host %s", host);
				gdm_slave_send_string (GDM_SOP_CHOSEN_LOCAL, host);
				gdm_slave_quick_exit (DISPLAY_REMANAGE);
			}
		}

		gdm_slave_quick_exit (DISPLAY_REMANAGE);
		break;
	}
}

static gboolean
is_session_magic (const char *session_name)
{
	return (strcmp (session_name, GDM_SESSION_DEFAULT) == 0 ||
		strcmp (session_name, GDM_SESSION_CUSTOM) == 0 ||
		strcmp (session_name, GDM_SESSION_FAILSAFE) == 0);
}

static char *
get_session_exec (const char *session_name, gboolean check_try_exec)
{
	char *file;
	char *full = NULL;
	VeConfig *cfg;
	static char *exec;
	static char *cached = NULL;
	char *tryexec;

	/* clear cache */
	if (session_name == NULL) {
		g_free (exec);
		exec = NULL;
		g_free (cached);
		cached = NULL;
		return NULL;
	}

	if (cached != NULL && strcmp (session_name, cached) == 0)
		return g_strdup (exec);

	g_free (exec);
	exec = NULL;
	g_free (cached);
	cached = g_strdup (session_name);

	/* Some ugly special casing for legacy "Default.desktop", oh well,
	 * we changed to "default.desktop" */
	if (g_ascii_strcasecmp (session_name, "default") == 0 ||
	    g_ascii_strcasecmp (session_name, "default.desktop") == 0) {
		full = ve_find_prog_in_path ("default.desktop", GdmSessDir);
	}

	if (full == NULL) {
		file = gdm_ensure_extension (session_name, ".desktop");
		full = ve_find_prog_in_path (file, GdmSessDir);
		g_free (file);
	}

	if (ve_string_empty (full) || access (full, R_OK) != 0) {
		g_free (full);
		if (is_session_magic (session_name)) {
			exec = g_strdup (session_name);
			return g_strdup (exec);
		} else {
			return NULL;
		}
	}

	cfg = ve_config_get (full);
	g_free (full);
	if (ve_config_get_bool (cfg, "Desktop Entry/Hidden=false"))
		return NULL;

	if (check_try_exec) {
		tryexec = ve_config_get_string (cfg, "Desktop Entry/TryExec");
		if ( ! ve_string_empty (tryexec) &&
		     ! ve_is_prog_in_path (tryexec, GdmDefaultPath) &&
		     ! ve_is_prog_in_path (tryexec, gdm_saved_getenv ("PATH"))) {
			g_free (tryexec);
			return NULL;
		}
		g_free (tryexec);
	}

	exec = ve_config_get_string (cfg, "Desktop Entry/Exec");
	return g_strdup (exec);
}

/* Note that this does check TryExec! while normally we don't check
 * it */
static gboolean
is_session_ok (const char *session_name)
{
	char *exec;
	gboolean ret = TRUE;

	/* these are always OK */
	if (strcmp (session_name, GDM_SESSION_FAILSAFE_GNOME) == 0 ||
	    strcmp (session_name, GDM_SESSION_FAILSAFE_XTERM) == 0)
		return TRUE;

	if (ve_string_empty (GdmSessDir))
		return is_session_magic (session_name);

	exec = get_session_exec (session_name, TRUE /* check_try_exec */);
	if (exec == NULL)
		ret = FALSE;
	g_free (exec);
	return ret;
}

static char *
find_a_session (void)
{
	char *try[] = {
		"Default",
		"default",
		"Gnome",
		"gnome",
		"GNOME",
		"Custom",
		"custom",
		"kde",
		"KDE",
		"failsafe",
		"Failsafe",
		NULL
	};
	int i;
	char *session;

	session = NULL;
	for (i = 0; try[i] != NULL && session == NULL; i ++) {
		if (is_session_ok (try[i]))
			session = g_strdup (try[i]);
	}
	return session;
}

static char *
find_prog (const char *name)
{
	char *path;
	int i;
	char *try[] = {
		"/usr/bin/X11/",
		"/usr/X11R6/bin/",
		"/opt/X11R6/bin/",
		"/usr/bin/",
		"/usr/openwin/bin/",
		"/usr/local/bin/",
		"/opt/gnome/bin/",
		EXPANDED_BINDIR "/",
		NULL
	};

	path = g_find_program_in_path (name);
	if (path != NULL &&
	    access (path, X_OK) == 0) {
		return path;
	}
	g_free (path);
	for (i = 0; try[i] != NULL; i++) {
		path = g_strconcat (try[i], name, NULL);
		if (access (path, X_OK) == 0) {
			return path;
		}
		g_free (path);
	}
	return NULL;
}

static gboolean
wipe_xsession_errors (struct passwd *pwent,
		      const char *home_dir,
		      gboolean home_dir_ok)
{
	gboolean wiped_something = FALSE;
	DIR *dir;
	struct dirent *ent;
	uid_t old = geteuid ();
	uid_t oldg = getegid ();

	seteuid (0);
	if G_UNLIKELY (setegid (pwent->pw_gid) != 0 ||
		       seteuid (pwent->pw_uid) != 0) {
		NEVER_FAILS_root_set_euid_egid (old, oldg);
		return FALSE;
	}

	if G_LIKELY (home_dir_ok) {
		char *filename = g_build_filename (home_dir,
						   ".xsession-errors",
						   NULL);
		if (access (filename, F_OK) == 0) {
			wiped_something = TRUE;
			VE_IGNORE_EINTR (unlink (filename));
		}
		g_free (filename);
	}

	VE_IGNORE_EINTR (dir = opendir ("/tmp"));
	if G_LIKELY (dir != NULL) {
		char *prefix = g_strdup_printf ("xses-%s.", pwent->pw_name);
		int prefixlen = strlen (prefix);
		VE_IGNORE_EINTR (ent = readdir (dir));
		while (ent != NULL) {
			if (strncmp (ent->d_name, prefix, prefixlen) == 0) {
				char *filename = g_strdup_printf ("/tmp/%s",
								  ent->d_name);
				wiped_something = TRUE;
				VE_IGNORE_EINTR (unlink (filename));
				g_free (filename);
			}
			VE_IGNORE_EINTR (ent = readdir (dir));
		}
		VE_IGNORE_EINTR (closedir (dir));
	}

	NEVER_FAILS_root_set_euid_egid (old, oldg);

	return wiped_something;
}

static int
open_xsession_errors (struct passwd *pwent,
		      gboolean failsafe,
		      const char *home_dir,
		      gboolean home_dir_ok)
{
	int logfd = -1;

	g_free (d->xsession_errors_filename);
	d->xsession_errors_filename = NULL;

        /* Log all output from session programs to a file,
	 * unless in failsafe mode which needs to work when there is
	 * no diskspace as well */
	if G_LIKELY ( ! failsafe && home_dir_ok) {
		char *filename = g_build_filename (home_dir,
						   ".xsession-errors",
						   NULL);
		uid_t old = geteuid ();
		uid_t oldg = getegid ();

		seteuid (0);
		if G_LIKELY (setegid (pwent->pw_gid) == 0 &&
			     seteuid (pwent->pw_uid) == 0) {
			/* unlink to be anal */
			VE_IGNORE_EINTR (unlink (filename));
			VE_IGNORE_EINTR (logfd = open (filename, O_EXCL|O_CREAT|O_TRUNC|O_WRONLY, 0644));
		}
		NEVER_FAILS_root_set_euid_egid (old, oldg);

		if G_UNLIKELY (logfd < 0) {
			gdm_error (_("%s: Could not open ~/.xsession-errors"),
				   "run_session_child");
			g_free (filename);
		} else {
			d->xsession_errors_filename = filename;
		}
	}

	/* let's try an alternative */
	if G_UNLIKELY (logfd < 0) {
		mode_t oldmode;

		char *filename = g_strdup_printf ("/tmp/xses-%s.XXXXXX",
						  pwent->pw_name);
		uid_t old = geteuid ();
		uid_t oldg = getegid ();

		seteuid (0);
		if G_LIKELY (setegid (pwent->pw_gid) == 0 &&
			     seteuid (pwent->pw_uid) == 0) {
			oldmode = umask (077);
			logfd = mkstemp (filename);
			umask (oldmode);
		}

		NEVER_FAILS_root_set_euid_egid (old, oldg);

		if G_LIKELY (logfd >= 0) {
			d->xsession_errors_filename = filename;
		} else {
			g_free (filename);
		}
	}

	return logfd;
}

#ifdef HAVE_SELINUX
/* This should be run just before we exec the user session */
static gboolean
gdm_selinux_setup (const char *login)
{
	security_context_t scontext;

	/* If selinux is not enabled, then we don't do anything */
	if ( ! is_selinux_enabled ())
		return TRUE;

	if (get_default_context((char*) login,0, &scontext) < 0) {
		gdm_error ("SELinux gdm login: unable to obtain default security context for %s.", login);
		/* note that this will be run when the .xsession-errors
		   is already being logged, so we can use stderr */
		gdm_fdprintf (2, "SELinux gdm login: unable to obtain default security context for %s.", login);
		return FALSE;
	}

	gdm_assert (scontext != NULL);

	if (setexeccon (scontext) != 0) {
		gdm_error ("SELinux gdm login: unable to set executable context %s.",
			  (char *)scontext);
		gdm_fdprintf (2, "SELinux gdm login: unable to set executable context %s.",
			      (char *)scontext);
		return FALSE;
	}

	freecon (scontext);

	return TRUE;
}
#endif /* HAVE_SELINUX */

static void
session_child_run (struct passwd *pwent,
		   int logfd,
		   gboolean failsafe,
		   const char *home_dir,
		   gboolean home_dir_ok,
		   const char *session,
		   const char *save_session,
		   const char *language,
		   const char *gnome_session,
		   gboolean usrcfgok,
		   gboolean savesess,
		   gboolean savelang)
{
	char *exec;
	const char *shell = NULL;
	VeConfig *dmrc = NULL;
	char *argv[4];

#ifdef CAN_USE_SETPENV
	extern char **newenv;
	int i;
#endif

	gdm_unset_signals ();
	if G_UNLIKELY (setsid() < 0)
		/* should never happen */
		gdm_error (_("%s: setsid() failed: %s!"),
			   "session_child_run", strerror(errno));

	ve_setenv ("XAUTHORITY", GDM_AUTHFILE (d), TRUE);

	/* Here we setup our 0,1,2 descriptors, we do it here
	 * nowdays rather then later on so that we get errors even
	 * from the PreSession script */
	if G_LIKELY (logfd >= 0) {
		VE_IGNORE_EINTR (dup2 (logfd, 1));
		VE_IGNORE_EINTR (dup2 (logfd, 2));
		VE_IGNORE_EINTR (close (logfd));
	} else {
		VE_IGNORE_EINTR (close (1));
		VE_IGNORE_EINTR (close (2));
		gdm_open_dev_null (O_RDWR); /* open stdout - fd 1 */
		gdm_open_dev_null (O_RDWR); /* open stderr - fd 2 */
	}

	VE_IGNORE_EINTR (close (0));
	gdm_open_dev_null (O_RDONLY); /* open stdin - fd 0 */

	/* Set this for the PreSession script */
	/* compatibility */
	ve_setenv ("GDMSESSION", session, TRUE);

	ve_setenv ("DESKTOP_SESSION", session, TRUE);

	/* Run the PreSession script */
	if G_UNLIKELY (gdm_slave_exec_script (d, GdmPreSession,
					      login, pwent,
					      TRUE /* pass_stdout */,
					      TRUE /* set_parent */) != EXIT_SUCCESS &&
		       /* ignore errors in failsafe modes */
		       ! failsafe) 
		/* If script fails reset X server and restart greeter */
		gdm_child_exit (DISPLAY_REMANAGE,
				_("%s: Execution of PreSession script returned > 0. Aborting."), "session_child_run");

	gdm_clearenv ();

	/* Prepare user session */
	ve_setenv ("XAUTHORITY", d->userauth, TRUE);
	ve_setenv ("DISPLAY", d->name, TRUE);
	ve_setenv ("LOGNAME", login, TRUE);
	ve_setenv ("USER", login, TRUE);
	ve_setenv ("USERNAME", login, TRUE);
	ve_setenv ("HOME", home_dir, TRUE);
	ve_setenv ("GDMSESSION", session, TRUE);
	ve_setenv ("DESKTOP_SESSION", session, TRUE);
	ve_setenv ("SHELL", pwent->pw_shell, TRUE);
	ve_unsetenv ("MAIL");	/* Unset $MAIL for broken shells */

	if (gnome_session != NULL)
		ve_setenv ("GDM_GNOME_SESSION", gnome_session, TRUE);

	/* Special PATH for root */
	if (pwent->pw_uid == 0)
		ve_setenv ("PATH", GdmRootPath, TRUE);
	else
		ve_setenv ("PATH", GdmDefaultPath, TRUE);

	/* Eeeeek, this no lookie as a correct language code,
	 * just use the system default */
	if G_UNLIKELY ( ! ve_string_empty (language) &&
			! ve_locale_exists (language)) {
		char *msg = g_strdup_printf (_("Language %s does not exist, using %s"),
					     language, _("System default"));
		gdm_error_box (d, GTK_MESSAGE_ERROR, msg);
		language = NULL;
	}

	/* Now still as root make the system authfile not readable by others,
	   and therefore not by the gdm user */
	VE_IGNORE_EINTR (chmod (GDM_AUTHFILE (d), 0640));

	setpgid (0, 0);
	
	umask (022);
	
	/* setup the verify env vars */
	if G_UNLIKELY ( ! gdm_verify_setup_env (d))
		gdm_child_exit (DISPLAY_REMANAGE,
				_("%s: Could not setup environment for %s. "
				  "Aborting."),
				"session_child_run", login);

	/* setup egid to the correct group,
	 * not to leave the egid around.  It's
	 * ok to gdm_fail here */
	NEVER_FAILS_setegid (pwent->pw_gid);

	VE_IGNORE_EINTR (chdir (home_dir));
	if G_UNLIKELY (errno != 0) {
		VE_IGNORE_EINTR (chdir ("/"));
	} else if (pwent->pw_uid != 0) {
		if (seteuid (pwent->pw_uid) == 0 &&
		    access (".ICEauthority", F_OK) == 0) {
			/* sanitize .ICEauthority to be of the correct
			 * permissions, if it exists */
			struct stat s;
			if (stat (home_dir, &s) == 0 &&
			    s.st_uid == pwent->pw_uid &&
			    stat (".ICEauthority", &s) &&
			    S_ISREG (s.st_mode) &&
			    (s.st_uid != pwent->pw_uid ||
			     s.st_gid != pwent->pw_gid ||
			     (s.st_mode & (S_IRWXG|S_IRWXO)))) {
				/* This may not work on NFS, but oh well, there
				 * this is beyond our help, but it's unlikely
				 * that it got screwed up when NFS was used
				 * in the first place */
				seteuid (0);
				/* only if we own the current directory */
				chown (".ICEauthority",
				       pwent->pw_uid,
				       pwent->pw_gid);
				chmod (".ICEauthority", S_IRUSR | S_IWUSR);
			}
		}
		seteuid (0);
	}

#ifdef HAVE_LOGINCAP
	if (setusercontext (NULL, pwent, pwent->pw_uid,
			    LOGIN_SETLOGIN | LOGIN_SETPATH |
			    LOGIN_SETPRIORITY | LOGIN_SETRESOURCES |
			    LOGIN_SETUMASK | LOGIN_SETUSER |
			    LOGIN_SETENV) < 0)
		gdm_child_exit (DISPLAY_REMANAGE,
				_("%s: setusercontext() failed for %s. "
				  "Aborting."), "session_child_run",
				login);
#else
	if G_UNLIKELY (setuid (pwent->pw_uid) < 0) 
		gdm_child_exit (DISPLAY_REMANAGE,
				_("%s: Could not become %s. Aborting."), "session_child_run", login);
#endif

	/* Only force GDM_LANG to something if there is other then
	 * system default selected.  Else let the session do whatever it
	 * does since we're using sys default */
	if ( ! ve_string_empty (language)) {
		ve_setenv ("LANG", language, TRUE);
		ve_setenv ("GDM_LANG", language, TRUE);
	}

	/* just in case there is some weirdness going on */
	VE_IGNORE_EINTR (chdir (home_dir));
	
	if (usrcfgok && savesess && home_dir_ok) {
		gchar *cfgstr = g_build_filename (home_dir, ".dmrc", NULL);
		if (dmrc == NULL)
			dmrc = ve_config_new (cfgstr);
		ve_config_set_string (dmrc, "Desktop/Session",
				      ve_sure_string (save_session));
		g_free (cfgstr);
	}
	
	if (usrcfgok && savelang && home_dir_ok) {
		gchar *cfgstr = g_build_filename (home_dir, ".dmrc", NULL);
		if (dmrc == NULL)
			dmrc = ve_config_new (cfgstr);
		if (ve_string_empty (language))
			/* we chose the system default language so wipe the
			 * lang key */
			ve_config_delete_key (dmrc, "Desktop/Language");
		else
			ve_config_set_string (dmrc, "Desktop/Language",
					      language);
		g_free (cfgstr);
	}

	if (dmrc != NULL) {
		mode_t oldmode;
		oldmode = umask (077);
		ve_config_save (dmrc, FALSE);
		ve_config_destroy (dmrc);
		dmrc = NULL;
		umask (oldmode);
	}

	closelog ();

	gdm_close_all_descriptors (3 /* from */, -1 /* except */, -1 /* except2 */);

	openlog ("gdm", LOG_PID, LOG_DAEMON);
	
	argv[0] = NULL;
	argv[1] = NULL;
	argv[2] = NULL;
	argv[3] = NULL;

	exec = NULL;
	if (strcmp (session, GDM_SESSION_FAILSAFE_XTERM) != 0 &&
	    strcmp (session, GDM_SESSION_FAILSAFE_GNOME) != 0) {
		exec = get_session_exec (session,
					 FALSE /* check_try_exec */);
		if G_UNLIKELY (exec == NULL) {
			gdm_error (_("%s: No Exec line in the session file: %s, starting failsafe GNOME"),
				   "session_child_run",
				   session);
			session = GDM_SESSION_FAILSAFE_GNOME;
			gdm_error_box
				(d, GTK_MESSAGE_ERROR,
				 _("The session you selected does not look valid.  I will run the GNOME failsafe session for you."));
		} else {
			/* HACK!, if failsafe, we really wish to run the
			   internal one */
			if (strcmp (exec, "failsafe") == 0) {
				session = GDM_SESSION_FAILSAFE_XTERM;
				exec = NULL;
			}
		}
	}

	if (exec != NULL) {
		/* cannot be possibly failsafe */
		if G_UNLIKELY (access (GdmXsession, X_OK) != 0) {
			gdm_error (_("%s: Cannot find or run the base Xsession script, will try GNOME failsafe"),
				   "session_child_run");
			session = GDM_SESSION_FAILSAFE_GNOME;
			exec = NULL;
			gdm_error_box
				(d, GTK_MESSAGE_ERROR,
				 _("Cannot find or run the base session script, will try the GNOME failsafe session for you."));
		} else {
			/* This is where everything is OK, and note that
			   we really DON'T care about leaks, we are going to
			   exec in just a bit */
			argv[0] = GdmXsession;
			argv[1] = exec;
			argv[2] = NULL;
		}
	}

	if (strcmp (session, GDM_SESSION_FAILSAFE_GNOME) == 0) {
		argv[0] = find_prog ("gnome-session");
		if G_UNLIKELY (argv[0] == NULL) {
			/* yaikes */
			gdm_error (_("%s: gnome-session not found for a failsafe GNOME session, trying xterm"),
				   "session_child_run");
			session = GDM_SESSION_FAILSAFE_XTERM;
			gdm_error_box
				(d, GTK_MESSAGE_ERROR,
				 _("Could not find the GNOME installation, "
				   "will try running the \"Failsafe xterm\" "
				   "session."));
		} else {
			argv[1] = "--failsafe";
			argv[2] = NULL;
			gdm_error_box
				(d, GTK_MESSAGE_INFO,
				 _("This is the Failsafe Gnome session.  "
				   "You will be logged into the 'Default' "
				   "session of Gnome with no startup scripts "
				   "run.  This is only to fix problems in "
				   "your installation."));
		}
		failsafe = TRUE;
	}

	/* an if and not an else, we could have done a fall-through
	 * to here in the above code if we can't find gnome-session */
	if (strcmp (session, GDM_SESSION_FAILSAFE_XTERM) == 0) {
		argv[0] = find_prog ("xterm");
		if (argv[0] == NULL) {
			gdm_error_box (d, GTK_MESSAGE_ERROR,
				       _("Cannot find \"xterm\" to start "
					 "a failsafe session."));
			/* nyah nyah nyah nyah nyah */
			/* 66 means no "session crashed" examine .xsession-errors dialog */
			_exit (66);
		} else {
			argv[1] = "-geometry";
			argv[2] = g_strdup_printf ("80x24-%d-%d",
						   d->lrh_offsetx,
						   d->lrh_offsety);
			argv[3] = NULL;
			gdm_error_box
				(d, GTK_MESSAGE_INFO,
				 _("This is the Failsafe xterm session.  "
				   "You will be logged into a terminal "
				   "console so that you may fix your system "
				   "if you cannot log in any other way.  "
				   "To exit the terminal emulator, type "
				   "'exit' and an enter into the window."));
			focus_first_x_window ("xterm");
		}
		failsafe = TRUE;
	} 

	gdm_debug ("Running %s %s %s for %s on %s",
		   argv[0],
		   ve_sure_string (argv[1]),
		   ve_sure_string (argv[2]),
		   login, d->name);

	if ( ! ve_string_empty (pwent->pw_shell)) {
		shell = pwent->pw_shell;
	} else {
		shell = "/bin/sh";
	}

	/* just a stupid test */
	if (strcmp (shell, "/sbin/nologin") == 0 ||
	    strcmp (shell, "/bin/false") == 0 ||
	    strcmp (shell, "/bin/true") == 0) {
		gdm_error (_("%s: User not allowed to log in"),
			   "session_child_run");
		gdm_error_box (d, GTK_MESSAGE_ERROR,
			       _("The system administrator has "
				 "disabled your account."));
		/* ends as if nothing bad happened */
		/* 66 means no "session crashed" examine .xsession-errors
		   dialog */
		_exit (66);
	}

#ifdef CAN_USE_SETPENV
	/* Call the function setpenv which instanciates the extern variable "newenv" */
	setpenv (login, (PENV_INIT | PENV_NOEXEC), NULL, NULL);
	
	/* Add the content of the "newenv" variable to the environment */
	for (i=0; newenv != NULL && newenv[i] != NULL; i++) {
		char *env_str = g_strdup (newenv[i]);
		char *p = strchr (env_str, '=');
		if (p != NULL) {
			/* Add the variable to the env */
			ve_setenv (env_str, &p[1], TRUE);
		}
		g_free (env_str);
	}
#endif

#ifdef HAVE_SELINUX
	if ( ! gdm_selinux_setup (pwent->pw_name)) {
		/* 66 means no "session crashed" examine .xsession-errors
		   dialog */
		gdm_error_box (d, GTK_MESSAGE_ERROR,
			       _("Error! Unable to set executable context."));
		_exit (66);
	}
#endif

	VE_IGNORE_EINTR (execv (argv[0], argv));

	/* will go to .xsession-errors */
	fprintf (stderr, _("%s: Could not exec %s %s %s"), 
		 "session_child_run",
		 argv[0],
		 ve_sure_string (argv[1]),
		 ve_sure_string (argv[2]));
	gdm_error ( _("%s: Could not exec %s %s %s"), 
		 "session_child_run",
		 argv[0],
		 ve_sure_string (argv[1]),
		 ve_sure_string (argv[2]));

	/* if we can't read and exec the session, then make a nice
	 * error dialog */
	gdm_error_box
		(d, GTK_MESSAGE_ERROR,
		 /* we can't really be any more specific */
		 _("Cannot start the session due to some "
		   "internal error."));
	
	/* ends as if nothing bad happened */
	_exit (0);
}

static void
finish_session_output (gboolean do_read)
{
	if G_LIKELY (d->session_output_fd >= 0)  {
		if (do_read)
			run_session_output (TRUE /* read_until_eof */);
		if (d->session_output_fd >= 0)  {
			VE_IGNORE_EINTR (close (d->session_output_fd));
			d->session_output_fd = -1;
		}
		if (d->xsession_errors_fd >= 0)  {
			VE_IGNORE_EINTR (close (d->xsession_errors_fd));
			d->xsession_errors_fd = -1;
		}
	}
}

static void
gdm_slave_session_start (void)
{
    struct passwd *pwent;
    char *save_session = NULL, *session = NULL, *language = NULL, *usrsess, *usrlang;
    char *gnome_session = NULL;
    gboolean savesess = FALSE, savelang = FALSE;
    gboolean usrcfgok = FALSE, authok = FALSE;
    const char *home_dir = NULL;
    gboolean home_dir_ok = FALSE;
    time_t session_start_time, end_time; 
    gboolean failsafe = FALSE;
    pid_t pid;
    GdmWaitPid *wp;
    uid_t uid;
    gid_t gid;
    int logpipe[2];
    int logfilefd;
    char *tmp;

    gdm_debug ("gdm_slave_session_start: Attempting session for user '%s'",
	       login);

    pwent = getpwnam (login);

    if G_UNLIKELY (pwent == NULL)  {
	    /* This is sort of an "assert", this should NEVER happen */
	    if (greet)
		    gdm_slave_whack_greeter();
	    gdm_slave_exit (DISPLAY_REMANAGE,
			    _("%s: User passed auth but getpwnam(%s) failed!"), "gdm_slave_session_start", login);
    }

    logged_in_uid = uid = pwent->pw_uid;
    logged_in_gid = gid = pwent->pw_gid;

    /* Run the PostLogin script */
    if G_UNLIKELY (gdm_slave_exec_script (d, GdmPostLogin,
					  login, pwent,
					  TRUE /* pass_stdout */,
					  TRUE /* set_parent */) != EXIT_SUCCESS &&
		   /* ignore errors in failsafe modes */
		   ! failsafe) {
	    gdm_verify_cleanup (d);
	    gdm_error (_("%s: Execution of PostLogin script returned > 0. Aborting."), "gdm_slave_session_start");
	    /* script failed so just try again */
	    return;
		
    }

    if G_UNLIKELY (pwent->pw_dir == NULL ||
		   ! g_file_test (pwent->pw_dir, G_FILE_TEST_IS_DIR)) {
	    char *msg = g_strdup_printf (
		     _("Your home directory is listed as:\n'%s'\n"
		       "but it does not appear to exist.  "
		       "Do you want to log in with the / (root) "
		       "directory as your home directory?\n\n"
		       "It is unlikely anything will work unless "
		       "you use a failsafe session."),
		     ve_sure_string (pwent->pw_dir));

	    gdm_error (_("%s: Home directory for %s: '%s' does not exist!"),
		       "gdm_slave_session_start",
		       login,
		       ve_sure_string (pwent->pw_dir));

	    /* Does the user want to piss off or try to do stupid crap? */
	    if ( ! gdm_failsafe_yesno (d, msg)) {
		    g_free (msg);
		    gdm_verify_cleanup (d);
		    session_started = FALSE;
		    return;
	    }

	    g_free (msg);

	    home_dir_ok = FALSE;
	    home_dir = "/";
    } else {
	    home_dir_ok = TRUE;
	    home_dir = pwent->pw_dir;
    }

    if G_UNLIKELY (setegid (pwent->pw_gid) != 0 ||
		   seteuid (pwent->pw_uid) != 0) {
	    gdm_error ("Cannot set effective user/group id");
	    gdm_verify_cleanup (d);
	    session_started = FALSE;
	    return;
    }

    if G_LIKELY (home_dir_ok) {
	    /* Sanity check on ~user/.dmrc */
	    usrcfgok = gdm_file_check ("gdm_slave_session_start", pwent->pw_uid,
				       home_dir, ".dmrc", TRUE, FALSE,
				       GdmUserMaxFile, GdmRelaxPerms);
    } else {
	    usrcfgok = FALSE;
    }

    if G_LIKELY (usrcfgok) {
	char *p;
	char *cfgfile = g_build_filename (home_dir, ".dmrc", NULL);
	VeConfig *cfg = ve_config_new (cfgfile);
	g_free (cfgfile);

	usrsess = ve_config_get_string (cfg, "Desktop/Session");
	if (usrsess == NULL)
		usrsess = g_strdup ("");

	/* this is just being truly anal about what users give us, and in case
	 * it looks like they may have included a path whack it. */
	p = strrchr (usrsess, '/');
	if (p != NULL) {
		char *tmp = g_strdup (p+1);
		g_free (usrsess);
		usrsess = tmp;
	}

	/* ugly workaround for migration */
	if ((strcmp (usrsess, "Default.desktop") == 0 ||
	     strcmp (usrsess, "Default") == 0) &&
	    ! ve_is_prog_in_path ("Default.desktop", GdmSessDir)) {
		g_free (usrsess);
		usrsess = g_strdup ("default");
		savesess = TRUE;
	}

	usrlang = ve_config_get_string (cfg, "Desktop/Language");
	if (usrlang == NULL)
		usrlang = g_strdup ("");

	ve_config_destroy (cfg);
    } else {
	usrsess = g_strdup ("");
	usrlang = g_strdup ("");
    }

    NEVER_FAILS_root_set_euid_egid (0, GdmGroupId);

    if (greet) {
	    tmp = gdm_ensure_extension (usrsess, ".desktop");
	    session = gdm_slave_greeter_ctl (GDM_SESS, tmp);
	    g_free (tmp);
	    language = gdm_slave_greeter_ctl (GDM_LANG, usrlang);
    } else {
	    session = g_strdup (usrsess);
	    language = g_strdup (usrlang);
    }

    tmp = gdm_strip_extension (session, ".desktop");
    g_free (session);
    session = tmp;

    if (ve_string_empty (session)) {
	    g_free (session);
	    session = find_a_session ();
	    if (session == NULL) {
		    /* we're running out of options */
		    session = g_strdup (GDM_SESSION_FAILSAFE_GNOME);
	    }
    }

    if G_LIKELY (ve_string_empty (language)) {
	    g_free (language);
	    language = NULL;
    }

    g_free (usrsess);
    g_free (usrlang);

    gdm_debug ("Initial setting: session: '%s' language: '%s'\n",
	       session, ve_sure_string (language));

    /* save this session as the users session */
    save_session = g_strdup (session);

    if (greet) {
	    char *ret = gdm_slave_greeter_ctl (GDM_SSESS, "");
	    if ( ! ve_string_empty (ret))
		    savesess = TRUE;
	    g_free (ret);

	    ret = gdm_slave_greeter_ctl (GDM_SLANG, "");
	    if ( ! ve_string_empty (ret))
		    savelang = TRUE;
	    g_free (ret);

	    gdm_debug ("gdm_slave_session_start: Authentication completed. Whacking greeter");

	    gdm_slave_whack_greeter ();
    }

    if (GdmKillInitClients)
	    gdm_server_whack_clients (d);

    /* Now that we will set up the user authorization we will
       need to run session_stop to whack it */
    session_started = TRUE;

    /* Setup cookie -- We need this information during cleanup, thus
     * cookie handling is done before fork()ing */

    if G_UNLIKELY (setegid (pwent->pw_gid) != 0 ||
		   seteuid (pwent->pw_uid) != 0) {
	    gdm_error ("Cannot set effective user/group id");
	    gdm_slave_quick_exit (DISPLAY_REMANAGE);
    }

    authok = gdm_auth_user_add (d, pwent->pw_uid,
				/* Only pass the home_dir if
				 * it was ok */
				home_dir_ok ? home_dir : NULL);

    /* FIXME: this should be smarter and only do this on out-of-diskspace
     * errors */
    if G_UNLIKELY ( ! authok && home_dir_ok) {
	    /* try wiping the .xsession-errors file (and perhaps other things)
	       in an attempt to gain disk space */
	    if (wipe_xsession_errors (pwent, home_dir, home_dir_ok)) {
		    gdm_error ("Tried wiping some old user session errors files "
			       "to make disk space and will try adding user auth "
			       "files again");
		    /* Try again */
		    authok = gdm_auth_user_add (d, pwent->pw_uid,
						/* Only pass the home_dir if
						 * it was ok */
						home_dir_ok ? home_dir : NULL);
	    }
    }

    NEVER_FAILS_root_set_euid_egid (0, GdmGroupId);
    
    if G_UNLIKELY ( ! authok) {
	    gdm_debug ("gdm_slave_session_start: Auth not OK");

	    gdm_error_box (d,
			   GTK_MESSAGE_ERROR,
			   _("GDM could not write to your authorization "
			     "file.  This could mean that you are out of "
			     "disk space or that your home directory could "
			     "not be opened for writing.  In any case, it "
			     "is not possible to log in.  Please contact "
			     "your system administrator"));

	    gdm_slave_session_stop (FALSE /* run_post_session */,
				    FALSE /* no_shutdown_check */);

	    gdm_slave_quick_exit (DISPLAY_REMANAGE);
    }

    if G_UNLIKELY (strcmp (session, GDM_SESSION_FAILSAFE_GNOME) == 0 ||
		   strcmp (session, GDM_SESSION_FAILSAFE_XTERM) == 0 ||
		   g_ascii_strcasecmp (session, "failsafe") == 0 /* hack */)
	    failsafe = TRUE;

    if G_LIKELY ( ! failsafe) {
	    char *exec = get_session_exec (session, FALSE /* check_try_exec */);
	    if ( ! ve_string_empty (exec) &&
		strcmp (exec, "failsafe") == 0)
		    failsafe = TRUE;
	    g_free (exec);
    }

    /* Write out the Xservers file */
    gdm_slave_send_num (GDM_SOP_WRITE_X_SERVERS, 0 /* bogus */);

    if G_LIKELY (d->dsp != NULL) {
	    Cursor xcursor;

	    XSetInputFocus (d->dsp, PointerRoot,
			    RevertToPointerRoot, CurrentTime);

	    /* return left pointer */
	    xcursor = XCreateFontCursor (d->dsp, GDK_LEFT_PTR);
	    XDefineCursor (d->dsp,
			   DefaultRootWindow (d->dsp),
			   xcursor);
	    XFreeCursor (d->dsp, xcursor);
	    XSync (d->dsp, False);
    }

    /* Init the ~/.xsession-errors stuff */
    d->xsession_errors_bytes = 0;
    d->xsession_errors_fd = -1;
    d->session_output_fd = -1;

    logfilefd = open_xsession_errors (pwent,
				      failsafe,
				      home_dir,
				      home_dir_ok);
    if G_UNLIKELY (logfilefd < 0 ||
		   pipe (logpipe) != 0) {
	    if (logfilefd >= 0)
		    VE_IGNORE_EINTR (close (logfilefd));
	    logfilefd = -1;
    }

    /* don't completely rely on this, the user
     * could reset time or do other crazy things */
    session_start_time = time (NULL);

    /* Start user process */
    gdm_sigchld_block_push ();
    gdm_sigterm_block_push ();
    pid = d->sesspid = fork ();
    if (pid == 0)
	    gdm_unset_signals ();
    gdm_sigterm_block_pop ();
    gdm_sigchld_block_pop ();

    switch (pid) {
	
    case -1:
	gdm_slave_exit (DISPLAY_REMANAGE, _("%s: Error forking user session"), "gdm_slave_session_start");
	
    case 0:
	if G_LIKELY (logfilefd >= 0) {
		VE_IGNORE_EINTR (close (logpipe[0]));
	}
	/* Never returns */
	session_child_run (pwent,
			   logpipe[1],
			   failsafe,
			   home_dir,
			   home_dir_ok,
			   session,
			   save_session,
			   language,
			   gnome_session,
			   usrcfgok,
			   savesess,
			   savelang);
	gdm_assert_not_reached ();
	
    default:
	break;
    }
    
    /* this clears internal cache */
    get_session_exec (NULL, FALSE);

    if G_LIKELY (logfilefd >= 0)  {
	    d->xsession_errors_fd = logfilefd;
	    d->session_output_fd = logpipe[0];
	    /* make the output read fd non-blocking */
	    fcntl (d->session_output_fd, F_SETFL, O_NONBLOCK);
	    VE_IGNORE_EINTR (close (logpipe[1]));
    }

    /* We must be root for this, and we are, but just to make sure */
    NEVER_FAILS_root_set_euid_egid (0, GdmGroupId);
    /* Reset all the process limits, pam may have set some up for our process and that
       is quite evil.  But pam is generally evil, so this is to be expected. */
    gdm_reset_limits ();

    g_free (session);
    g_free (save_session);
    g_free (language);
    g_free (gnome_session);

    gdm_slave_send_num (GDM_SOP_SESSPID, pid);

    gdm_sigchld_block_push ();
    wp = slave_waitpid_setpid (d->sesspid);
    gdm_sigchld_block_pop ();

    slave_waitpid (wp);

    d->sesspid = 0;

    /* finish reading the session output if any of it is still there */
    finish_session_output (TRUE);

    /* Now still as root make the system authfile readable by others,
       and therefore by the gdm user */
    VE_IGNORE_EINTR (chmod (GDM_AUTHFILE (d), 0644));

    end_time = time (NULL);

    gdm_debug ("Session: start_time: %ld end_time: %ld",
	       (long)session_start_time, (long)end_time);

    /* 66 is a very magical number signifying failure in GDM */
    if G_UNLIKELY ((d->last_sess_status != 66) &&
		   (/* sanity */ end_time >= session_start_time) &&
		   (end_time - 10 <= session_start_time) &&
		   /* only if the X server still exist! */
		   d->servpid > 1) {
	    gdm_debug ("Session less than 10 seconds!");

	    /* FIXME: perhaps do some checking to display a better error,
	     * such as gnome-session missing and such things. */
	    gdm_error_box_full (d,
				GTK_MESSAGE_WARNING,
				_("Your session only lasted less than "
				  "10 seconds.  If you have not logged out "
				  "yourself, this could mean that there is "
				  "some installation problem or that you may "
				  "be out of diskspace.  Try logging in with "
				  "one of the failsafe sessions to see if you "
				  "can fix this problem."),
				(d->xsession_errors_filename != NULL) ?
			       	  _("View details (~/.xsession-errors file)") :
				  NULL,
				d->xsession_errors_filename,
				uid, gid);
    }

    gdm_slave_session_stop (pid != 0 /* run_post_session */,
			    FALSE /* no_shutdown_check */);

    gdm_debug ("gdm_slave_session_start: Session ended OK (now all finished)");
}


/* Stop any in progress sessions */
static void
gdm_slave_session_stop (gboolean run_post_session,
			gboolean no_shutdown_check)
{
    struct passwd *pwent;
    char *x_servers_file;
    char *local_login;

    in_session_stop ++;

    session_started = FALSE;

    local_login = login;
    login = NULL;

    /* don't use NEVER_FAILS_ here this can be called from places
       kind of exiting and it's ok if this doesn't work (when shouldn't
       it work anyway? */
    seteuid (0);
    setegid (0);

    gdm_slave_send_num (GDM_SOP_SESSPID, 0);

    /* Now still as root make the system authfile not readable by others,
       and therefore not by the gdm user */
    if (GDM_AUTHFILE (d) != NULL) {
	    VE_IGNORE_EINTR (chmod (GDM_AUTHFILE (d), 0640));
    }

    gdm_debug ("gdm_slave_session_stop: %s on %s", local_login, d->name);

    /* Note we use the info in the structure here since if we get passed
     * a 0 that means the process is already dead.
     * FIXME: Maybe we should waitpid here, note make sure this will
     * not create a hang! */
    gdm_sigchld_block_push ();
    if (d->sesspid > 1)
	    kill (- (d->sesspid), SIGTERM);
    gdm_sigchld_block_pop ();

    /* HACK:
       This is to fix #126071, that is kill processes that may still hold open
       fd's in the home directory to allow a clean unmount.  However note of course
       that this is a race. */
    gdm_server_whack_clients (d);

#if defined(_POSIX_PRIORITY_SCHEDULING) && defined(HAVE_SCHED_YIELD)
    /* let the other processes die perhaps or whatnot */
    sched_yield ();
#endif

    finish_session_output (run_post_session /* do_read */);
    
    if (local_login == NULL)
	    pwent = NULL;
    else
	    pwent = getpwnam (local_login);	/* PAM overwrites our pwent */

    x_servers_file = gdm_make_filename (GdmServAuthDir,
					d->name, ".Xservers");

    /* if there was a session that ran, run the PostSession script */
    if (run_post_session) {
	    /* Execute post session script */
	    gdm_debug ("gdm_slave_session_stop: Running post session script");
	    gdm_slave_exec_script (d, GdmPostSession, local_login, pwent,
				   FALSE /* pass_stdout */,
				   TRUE /* set_parent */);
    }

    VE_IGNORE_EINTR (unlink (x_servers_file));
    g_free (x_servers_file);

    g_free (local_login);

    if (pwent != NULL) {
	    seteuid (0); /* paranoia */
	    /* Remove display from ~user/.Xauthority */
	    if G_LIKELY (setegid (pwent->pw_gid) == 0 &&
			 seteuid (pwent->pw_uid) == 0) {
		    gdm_auth_user_remove (d, pwent->pw_uid);
	    }

	    /* don't use NEVER_FAILS_ here this can be called from places
	       kind of exiting and it's ok if this doesn't work (when shouldn't
	       it work anyway? */
	    seteuid (0);
	    setegid (0);
    }

    logged_in_uid = -1;
    logged_in_gid = -1;

    /* things are going to be killed, so ignore errors */
    XSetErrorHandler (ignore_xerror_handler);

    gdm_verify_cleanup (d);

    in_session_stop --;

    if (need_to_quit_after_session_stop) {
	    gdm_debug ("gdm_slave_session_stop: Final cleanup");

	    gdm_slave_quick_exit (exit_code_to_use);
    }

#ifdef __linux__
    /* If on linux and the runlevel is 0 or 6 and not the runlevel that
       we were started in, then we are rebooting or halting.
       Probably the user selected shutdown or reboot from the logout
       menu.  In this case we can really just sleep for a few seconds and
       basically wait to be killed.  I'll set the default for 30 seconds
       and let people yell at me if this breaks something.  It shouldn't.
       In fact it should fix things so that the login screen is not brought
       up again and then whacked.  Waiting is safer then DISPLAY_ABORT,
       since if we really do get this wrong, then at the worst case the
       user will wait for a few moments. */
    if ( ! need_to_quit_after_session_stop &&
	 ! no_shutdown_check &&
	access ("/sbin/runlevel", X_OK) == 0) {
	    char ign;
	    int rnl;
	    FILE *fp = popen ("/sbin/runlevel", "r");
	    if (fp != NULL &&
		fscanf (fp, "%c %d", &ign, &rnl) == 2 &&
		(rnl == 0 || rnl == 6) &&
		rnl != gdm_normal_runlevel) {
		    /* this is a stupid loop, but we may be getting signals,
		       so we don't want to just do sleep (30) */
		    time_t c = time (NULL);
		    gdm_info (_("GDM detected a shutdown or reboot "
				"in progress."));
		    pclose (fp);
		    while (c + 30 >= time (NULL)) {
			    struct timeval tv;
			    /* Wait 30 seconds. */
			    tv.tv_sec = 30;
			    tv.tv_usec = 0;
			    select (0, NULL, NULL, NULL, &tv);
			    /* don't want to use sleep since we're using alarm
			       for pinging */
		    }
		    /* hmm, didn't get TERM, weird */
	    } else if (fp != NULL) {
		    pclose (fp);
	    }
    }
#endif /* __linux__ */
}

static void
gdm_slave_term_handler (int sig)
{
	static gboolean got_term_before = FALSE;

	gdm_in_signal++;
	gdm_wait_for_ack = FALSE;

	gdm_debug ("gdm_slave_term_handler: %s got TERM/INT signal", d->name);

	exit_code_to_use = DISPLAY_ABORT;
	need_to_quit_after_session_stop = TRUE;

	if (already_in_slave_start_jmp ||
	    (got_term_before && in_session_stop > 0)) {
		gdm_sigchld_block_push ();
		/* be very very very nasty to the extra process if the user is really
		   trying to get rid of us */
		if (extra_process > 1)
			kill (-(extra_process), SIGKILL);
		/* also be very nasty to the X server at this stage */
		if (d->servpid > 1)
			kill (d->servpid, SIGKILL);
		gdm_sigchld_block_pop ();
		gdm_in_signal--;
		got_term_before = TRUE;
		/* we're already quitting, just a matter of killing all the processes */
		return;
	}
	got_term_before = TRUE;

	/* just in case this was set to something else, like during
	 * server reinit */
	XSetIOErrorHandler (gdm_slave_xioerror_handler);

	if (in_session_stop > 0) {
		/* the need_to_quit_after_session_stop is now set so things will
		   work out right */
		gdm_in_signal--;
		return;
	}

	if (session_started) {
		SIGNAL_EXIT_WITH_JMP (d, JMP_SESSION_STOP_AND_QUIT);
	} else {
		SIGNAL_EXIT_WITH_JMP (d, JMP_JUST_QUIT_QUICKLY);
	}

	/* never reached */
	gdm_in_signal--;
}

/* called on alarms to ping */
static void
gdm_slave_alrm_handler (int sig)
{
	static gboolean in_ping = FALSE;

	if G_UNLIKELY (already_in_slave_start_jmp)
		return;

	gdm_in_signal++;

	gdm_debug ("gdm_slave_alrm_handler: %s got ARLM signal, "
		   "to ping display", d->name);

	if G_UNLIKELY (d->dsp == NULL) {
		gdm_in_signal --;
		/* huh? */
		return;
	}

	if G_UNLIKELY (in_ping) {
		slave_start_jmp_error_to_print = 
			g_strdup_printf (_("Ping to %s failed, whacking display!"),
					 d->name);
		need_to_quit_after_session_stop = TRUE;
		exit_code_to_use = DISPLAY_REMANAGE;

		if (session_started) {
			SIGNAL_EXIT_WITH_JMP (d, JMP_SESSION_STOP_AND_QUIT);
		} else {
			SIGNAL_EXIT_WITH_JMP (d, JMP_JUST_QUIT_QUICKLY);
		}
	}

	in_ping = TRUE;

	/* schedule next alarm */
	alarm (GdmPingInterval);

	XSync (d->dsp, True);

	in_ping = FALSE;

	gdm_in_signal --;
}

/* Called on every SIGCHLD */
void 
gdm_slave_child_handler (int sig)
{
    gint status;
    pid_t pid;
    uid_t old;

    if G_UNLIKELY (already_in_slave_start_jmp)
	    return;

    gdm_in_signal++;

    gdm_debug ("gdm_slave_child_handler");

    old = geteuid ();
    if (old != 0)
	    seteuid (0);
    
    while ((pid = waitpid (-1, &status, WNOHANG)) > 0) {
        GSList *li;

	gdm_debug ("gdm_slave_child_handler: %d died", pid);

	for (li = slave_waitpids; li != NULL; li = li->next) {
		GdmWaitPid *wp = li->data;
		if (wp->pid == pid) {
			wp->pid = -1;
			if (slave_waitpid_w >= 0) {
				VE_IGNORE_EINTR (write (slave_waitpid_w, "!", 1));
			}
		}
	}
	
	if (WIFEXITED (status))
	    gdm_debug ("gdm_slave_child_handler: %d returned %d",
		       (int)pid, (int)WEXITSTATUS (status));
	if (WIFSIGNALED (status))
	    gdm_debug ("gdm_slave_child_handler: %d died of %d",
		       (int)pid, (int)WTERMSIG (status));

	if (pid == d->greetpid && greet) {
		if (WIFEXITED (status) &&
		    WEXITSTATUS (status) == DISPLAY_RESTARTGREETER) {
			/* FIXME: shouldn't do this from
			   a signal handler */
			/*gdm_slave_desensitize_config ();*/

			greet = FALSE;
			d->greetpid = 0;
			whack_greeter_fds ();
			gdm_slave_send_num (GDM_SOP_GREETPID, 0);

			do_restart_greeter = TRUE;
			if (restart_greeter_now) {
				slave_waitpid_notify ();
			} else {
				interrupted = TRUE;
			}
			continue;
		}

		whack_greeter_fds ();

		/* if greet is TRUE, then the greeter died outside of our
		 * control really, so clean up and die, something is wrong
		 * The greeter is only allowed to pass back these
		 * exit codes, else we'll just remanage */
		if (WIFEXITED (status) &&
		    (WEXITSTATUS (status) == DISPLAY_ABORT ||
		     WEXITSTATUS (status) == DISPLAY_REBOOT ||
		     WEXITSTATUS (status) == DISPLAY_HALT ||
		     WEXITSTATUS (status) == DISPLAY_SUSPEND ||
		     WEXITSTATUS (status) == DISPLAY_RUN_CHOOSER ||
		     WEXITSTATUS (status) == DISPLAY_RESTARTGDM ||
		     WEXITSTATUS (status) == DISPLAY_GREETERFAILED)) {
			exit_code_to_use = WEXITSTATUS (status);
			SIGNAL_EXIT_WITH_JMP (d, JMP_JUST_QUIT_QUICKLY);
		} else {
			if (WIFSIGNALED (status) &&
			    (WTERMSIG (status) == SIGSEGV ||
			     WTERMSIG (status) == SIGABRT ||
			     WTERMSIG (status) == SIGPIPE ||
			     WTERMSIG (status) == SIGBUS)) {
				exit_code_to_use = DISPLAY_GREETERFAILED;
				SIGNAL_EXIT_WITH_JMP (d, JMP_JUST_QUIT_QUICKLY);
			} else {
				/* weird error return, interpret as failure */
				if (WIFEXITED (status) &&
				    WEXITSTATUS (status) == 1)
					exit_code_to_use = DISPLAY_GREETERFAILED;
				SIGNAL_EXIT_WITH_JMP (d, JMP_JUST_QUIT_QUICKLY);
			}
		}
	} else if (pid != 0 && pid == d->sesspid) {
		d->sesspid = 0;
		if (WIFEXITED (status))
			d->last_sess_status = WEXITSTATUS (status);
		else
			d->last_sess_status = -1;
	} else if (pid != 0 && pid == d->chooserpid) {
		d->chooserpid = 0;
	} else if (pid != 0 && pid == d->servpid) {
		if (d->servstat == SERVER_RUNNING)
			gdm_server_whack_lockfile (d);
		d->servstat = SERVER_DEAD;
		d->servpid = 0;
		gdm_server_wipe_cookies (d);
		gdm_slave_whack_temp_auth_file ();

		gdm_slave_send_num (GDM_SOP_XPID, 0);

		/* whack the session good */
		if (d->sesspid > 1) {
			gdm_slave_send_num (GDM_SOP_SESSPID, 0);
			kill (- (d->sesspid), SIGTERM);
		}
		if (d->greetpid > 1) {
			gdm_slave_send_num (GDM_SOP_GREETPID, 0);
			kill (d->greetpid, SIGTERM);
		}
		if (d->chooserpid > 1) {
			gdm_slave_send_num (GDM_SOP_CHOOSERPID, 0);
			kill (d->chooserpid, SIGTERM);
		}

		/* just in case we restart again wait at least
		   one sec to avoid races */
		if (d->sleep_before_run < 1)
			d->sleep_before_run = 1;
	} else if (pid == extra_process) {
		/* an extra process died, yay! */
		extra_process = 0;
	    	extra_status = status;
	}
    }
    if (old != 0)
	    seteuid (old);

    gdm_in_signal--;
}

static void
gdm_slave_handle_usr2_message (void)
{
	char buf[256];
	size_t count;
	char **vec;
	int i;

	VE_IGNORE_EINTR (count = read (d->slave_notify_fd, buf, sizeof (buf) -1));
	if (count <= 0) {
		return;
	}

	buf[count] = '\0';

	vec = g_strsplit (buf, "\n", -1);
	if (vec == NULL) {
		return;
	}

	for (i = 0; vec[i] != NULL; i++) {
		char *s = vec[i];
		if (s[0] == GDM_SLAVE_NOTIFY_ACK) {
			gdm_got_ack = TRUE;
			g_free (gdm_ack_response);
			if (s[1] != '\0')
				gdm_ack_response = g_strdup (&s[1]);
			else
				gdm_ack_response = NULL;
		} else if (s[0] == GDM_SLAVE_NOTIFY_KEY) {
			slave_waitpid_notify ();
			unhandled_notifies =
				g_list_append (unhandled_notifies,
					       g_strdup (&s[1]));
		} else if (s[0] == GDM_SLAVE_NOTIFY_COMMAND) {
			if (strcmp (&s[1], GDM_NOTIFY_DIRTY_SERVERS) == 0) {
				/* never restart flexi servers
				 * they whack themselves */
				if (d->type != TYPE_FLEXI_XNEST &&
				    d->type != TYPE_FLEXI)
					remanage_asap = TRUE;
			} else if (strcmp (&s[1], GDM_NOTIFY_SOFT_RESTART_SERVERS) == 0) {
				/* never restart flexi servers,
				 * they whack themselves */
				/* FIXME: here we should handle actual
				 * restarts of flexi servers, but it probably
				 * doesn't matter */
				if (d->type != TYPE_FLEXI_XNEST &&
				    d->type != TYPE_FLEXI) {
					if ( ! d->logged_in) {
						if (gdm_in_signal > 0) {
							exit_code_to_use = DISPLAY_REMANAGE;
							SIGNAL_EXIT_WITH_JMP (d, JMP_JUST_QUIT_QUICKLY);
						} else {
							/* FIXME: are we ever not in signal here? */
							gdm_slave_quick_exit (DISPLAY_REMANAGE);
						}
					} else {
						remanage_asap = TRUE;
					}
				}
			} else if (strcmp (&s[1], GDM_NOTIFY_GO) == 0) {
				gdm_wait_for_go = FALSE;
			} else if (strcmp (&s[1], GDM_NOTIFY_TWIDDLE_POINTER) == 0) {
				gdm_twiddle_pointer (d);
			}
		}
	}

	g_strfreev (vec);
}

static void
gdm_slave_usr2_handler (int sig)
{
	gdm_in_signal++;
	in_usr2_signal++;

	gdm_debug ("gdm_slave_usr2_handler: %s got USR2 signal", d->name);

	gdm_slave_handle_usr2_message ();

	in_usr2_signal--;
	gdm_in_signal--;
}

/* Minor X faults */
static gint
gdm_slave_xerror_handler (Display *disp, XErrorEvent *evt)
{
    gdm_debug ("gdm_slave_xerror_handler: X error - display doesn't respond");
    return (0);
}

/* We respond to fatal errors by restarting the display */
static gint
gdm_slave_xioerror_handler (Display *disp)
{
	if (already_in_slave_start_jmp) {
		/* eki eki eki, this is not good,
		   should only happen if we get some io error after
		   we have gotten a SIGTERM */
		SIGNAL_EXIT_WITH_JMP (d, JMP_JUST_QUIT_QUICKLY);
	}

	gdm_in_signal++;

	/* Display is all gone */
	d->dsp = NULL;

	if ((d->type == TYPE_LOCAL ||
	     d->type == TYPE_FLEXI) &&
	    (do_xfailed_on_xio_error ||
	     d->starttime + 5 >= time (NULL))) {
		exit_code_to_use = DISPLAY_XFAILED;
	} else {
		exit_code_to_use = DISPLAY_REMANAGE;
	}

	slave_start_jmp_error_to_print =
		g_strdup_printf (_("%s: Fatal X error - Restarting %s"), 
				 "gdm_slave_xioerror_handler", d->name);

	need_to_quit_after_session_stop = TRUE;

	if (session_started) {
		SIGNAL_EXIT_WITH_JMP (d, JMP_SESSION_STOP_AND_QUIT);
	} else {
		SIGNAL_EXIT_WITH_JMP (d, JMP_JUST_QUIT_QUICKLY);
	}

	/* never reached */
	gdm_in_signal--;

	return 0;
}

/* return true for "there was an interruption received",
   and interrupted will be TRUE if we are actually interrupted from doing what
   we want.  If FALSE is returned, just continue on as we would normally */
static gboolean
check_for_interruption (const char *msg)
{
	/* Hell yeah we were interrupted, the greeter died */
	if (msg == NULL) {
		interrupted = TRUE;
		return TRUE;
	}

	if (msg[0] == BEL) {
		/* Different interruptions come here */
		/* Note that we don't want to actually do anything.  We want
		 * to just set some flag and go on and schedule it after we
		 * dump out of the login in the main login checking loop */
		switch (msg[1]) {
		case GDM_INTERRUPT_TIMED_LOGIN:
			/* only allow timed login if display is local,
			 * it is allowed for this display (it's only allowed
			 * for the first local display) and if it's set up
			 * correctly */
			if ((d->console || GdmAllowRemoteAutoLogin) 
                            && d->timed_login_ok &&
			    ! ve_string_empty (ParsedTimedLogin) &&
                            strcmp (ParsedTimedLogin, gdm_root_user ()) != 0 &&
			    GdmTimedLoginDelay > 0) {
				do_timed_login = TRUE;
			}
			break;
		case GDM_INTERRUPT_CONFIGURE:
			if (d->console &&
			    GdmConfigAvailable &&
			    GdmSystemMenu &&
			    ! ve_string_empty (GdmConfigurator)) {
				do_configurator = TRUE;
			}
			break;
		case GDM_INTERRUPT_SUSPEND:
			if (d->console &&
			    GdmSystemMenu &&
			    ! ve_string_empty (GdmSuspend)) {
				gdm_slave_send (GDM_SOP_SUSPEND_MACHINE,
						FALSE /* wait_for_ack */);
			}
			/* Not interrupted, continue reading input,
			 * just proxy this to the master server */
			return TRUE;
		case GDM_INTERRUPT_LOGIN_SOUND:
			if (d->console &&
			    ! ve_string_empty (GdmSoundProgram) &&
			    ! ve_string_empty (GdmSoundOnLoginFile) &&
			    access (GdmSoundProgram, X_OK) == 0 &&
			    access (GdmSoundOnLoginFile, F_OK) == 0) {
				pid_t pid;

				gdm_sigchld_block_push ();
				gdm_sigterm_block_push ();
				pid = fork ();
				if (pid == 0)
					gdm_unset_signals ();
				gdm_sigterm_block_pop ();
				gdm_sigchld_block_pop ();

				if (pid == 0) {
					setsid ();
					seteuid (0);
					setegid (0);
					execl (GdmSoundProgram,
					       GdmSoundProgram,
					       GdmSoundOnLoginFile,
					       NULL);

					_exit (0);
				}
			} else {
				gdm_error (_("Login sound requested on non-local display or the play software cannot be run or the sound does not exist"));
			}
			return TRUE;
		case GDM_INTERRUPT_SELECT_USER:
			gdm_verify_select_user (&msg[2]);
			break;
		case GDM_INTERRUPT_THEME:
			g_free (d->theme_name);
			d->theme_name = NULL;
			if ( ! ve_string_empty (&msg[2]))
				d->theme_name = g_strdup (&msg[2]);
			gdm_slave_send_string (GDM_SOP_CHOSEN_THEME, &msg[2]);
			return TRUE;
		default:
			break;
		}

		/* this was an interruption, if it wasn't
		 * handled then the user will just get an error as if he
		 * entered an invalid login or passward.  Seriously BEL
		 * cannot be part of a login/password really */
		interrupted = TRUE;
		return TRUE;
	}
	return FALSE;
}


char * 
gdm_slave_greeter_ctl (char cmd, const char *str)
{
    char *buf = NULL;
    int c;

    /* There is no spoon^H^H^H^H^Hgreeter */
    if G_UNLIKELY ( ! greet)
	    return NULL;

    check_notifies_now ();

    if ( ! ve_string_empty (str)) {
	    gdm_fdprintf (greeter_fd_out, "%c%c%s\n", STX, cmd, str);
    } else {
	    gdm_fdprintf (greeter_fd_out, "%c%c\n", STX, cmd);
    }

#if defined(_POSIX_PRIORITY_SCHEDULING) && defined(HAVE_SCHED_YIELD)
    /* let the other process (greeter) do its stuff */
    sched_yield ();
#endif

    do {
      g_free (buf);
      buf = NULL;
      /* Skip random junk that might have accumulated */
      do {
	    c = gdm_fdgetc (greeter_fd_in);
      } while (c != EOF && c != STX);
    
      if (c == EOF ||
	  (buf = gdm_fdgets (greeter_fd_in)) == NULL) {
	      interrupted = TRUE;
	      /* things don't seem well with the greeter, it probably died */
	      return NULL;
      }
    } while (check_for_interruption (buf) && ! interrupted);

    /* user responses take kind of random amount of time */
    gdm_random_tick ();

    if ( ! ve_string_empty (buf)) {
	    return buf;
    } else {
	    g_free (buf);
	    return NULL;
    }
}

void
gdm_slave_greeter_ctl_no_ret (char cmd, const char *str)
{
	g_free (gdm_slave_greeter_ctl (cmd, str));
}

static void 
gdm_slave_quick_exit (gint status)
{
    /* just for paranoia's sake */
    /* don't use NEVER_FAILS_ here this can be called from places
       kind of exiting and it's ok if this doesn't work (when shouldn't
       it work anyway? */
    seteuid (0);
    setegid (0);

    if (d != NULL) {
	    gdm_debug ("gdm_slave_quick_exit: Will kill everything from the display");

	    /* just in case we do get the XIOError,
	       don't run session_stop since we've
	       requested a quick exit */
	    session_started = FALSE;

	    /* No need to send the PIDS to the daemon
	     * since we'll just exit cleanly */

	    /* Push and never pop */
	    gdm_sigchld_block_push ();

	    /* Kill children where applicable */
	    if (d->greetpid > 1)
		    kill (d->greetpid, SIGTERM);
	    d->greetpid = 0;

	    if (d->chooserpid > 1)
		    kill (d->chooserpid, SIGTERM);
	    d->chooserpid = 0;

	    if (d->sesspid > 1)
		    kill (-(d->sesspid), SIGTERM);
	    d->sesspid = 0;

	    if (extra_process > 1)
		    kill (-(extra_process), SIGTERM);
	    extra_process = 0;

	    gdm_verify_cleanup (d);
	    gdm_server_stop (d);

	    if (d->servpid > 1)
		    kill (d->servpid, SIGTERM);
	    d->servpid = 0;

	    gdm_debug ("gdm_slave_quick_exit: Killed everything from the display");
    }

    _exit (status);
}

static void 
gdm_slave_exit (gint status, const gchar *format, ...)
{
    va_list args;
    gchar *s;

    va_start (args, format);
    s = g_strdup_vprintf (format, args);
    va_end (args);
    
    gdm_error ("%s", s);
    
    g_free (s);

    gdm_slave_quick_exit (status);
}

static void 
gdm_child_exit (gint status, const gchar *format, ...)
{
    va_list args;
    gchar *s;

    va_start (args, format);
    s = g_strdup_vprintf (format, args);
    va_end (args);
    
    syslog (LOG_ERR, "%s", s);
    
    g_free (s);

    _exit (status);
}

void
gdm_slave_whack_temp_auth_file (void)
{
	uid_t old;

	old = geteuid ();
	if (old != 0)
		seteuid (0);
	if (d->xnest_temp_auth_file != NULL) {
		VE_IGNORE_EINTR (unlink (d->xnest_temp_auth_file));
	}
	g_free (d->xnest_temp_auth_file);
	d->xnest_temp_auth_file = NULL;
	if (old != 0)
		seteuid (old);
}

static void
create_temp_auth_file (void)
{
	if (d->type == TYPE_FLEXI_XNEST &&
	    d->xnest_auth_file != NULL) {
		if (d->xnest_temp_auth_file != NULL) {
			VE_IGNORE_EINTR (unlink (d->xnest_temp_auth_file));
		}
		g_free (d->xnest_temp_auth_file);
		d->xnest_temp_auth_file =
			copy_auth_file (d->server_uid,
					GdmUserId,
					d->xnest_auth_file);
	}
}

static void
set_xnest_parent_stuff (void)
{
	if (d->type == TYPE_FLEXI_XNEST) {
		ve_setenv ("GDM_PARENT_DISPLAY", d->xnest_disp, TRUE);
		if (d->xnest_temp_auth_file != NULL) {
			ve_setenv ("GDM_PARENT_XAUTHORITY",
				      d->xnest_temp_auth_file, TRUE);
			g_free (d->xnest_temp_auth_file);
			d->xnest_temp_auth_file = NULL;
		}
	}
}

static gint
gdm_slave_exec_script (GdmDisplay *d, const gchar *dir, const char *login,
		       struct passwd *pwent, gboolean pass_stdout,
		       gboolean set_parent)
{
    pid_t pid;
    char *script;
    gchar **argv;
    gint status;
    char *x_servers_file;

    if G_UNLIKELY (!d || ve_string_empty (dir))
	return EXIT_SUCCESS;

    script = g_build_filename (dir, d->name, NULL);
    if (access (script, R_OK|X_OK) != 0) {
	    g_free (script);
	    script = NULL;
    }
    if (script == NULL &&
	! ve_string_empty (d->hostname)) {
	    script = g_build_filename (dir, d->hostname, NULL);
	    if (access (script, R_OK|X_OK) != 0) {
		    g_free (script);
		    script = NULL;
	    }
    }
    if (script == NULL &&
	d->type == TYPE_XDMCP) {
	    script = g_build_filename (dir, "XDMCP", NULL);
	    if (access (script, R_OK|X_OK) != 0) {
		    g_free (script);
		    script = NULL;
	    }
    }
    if (script == NULL &&
	SERVER_IS_FLEXI (d)) {
	    script = g_build_filename (dir, "Flexi", NULL);
	    if (access (script, R_OK|X_OK) != 0) {
		    g_free (script);
		    script = NULL;
	    }
    }
    if (script == NULL) {
	    script = g_build_filename (dir, "Default", NULL);
	    if (access (script, R_OK|X_OK) != 0) {
		    g_free (script);
		    script = NULL;
	    }
    }
    
    if (script == NULL) {
	    return EXIT_SUCCESS;
    }

    if (set_parent)
	    create_temp_auth_file ();

    pid = gdm_fork_extra ();

    switch (pid) {
	    
    case 0:
        closelog ();

	VE_IGNORE_EINTR (close (0));
	gdm_open_dev_null (O_RDONLY); /* open stdin - fd 0 */

	if ( ! pass_stdout) {
		VE_IGNORE_EINTR (close (1));
		VE_IGNORE_EINTR (close (2));
		/* No error checking here - if it's messed the best response
		 * is to ignore & try to continue */
		gdm_open_dev_null (O_RDWR); /* open stdout - fd 1 */
		gdm_open_dev_null (O_RDWR); /* open stderr - fd 2 */
	}

	gdm_close_all_descriptors (3 /* from */, -1 /* except */, -1 /* except2 */);

	openlog ("gdm", LOG_PID, LOG_DAEMON);

        if (login != NULL) {
	        ve_setenv ("LOGNAME", login, TRUE);
	        ve_setenv ("USER", login, TRUE);
	        ve_setenv ("USERNAME", login, TRUE);
        } else {
	        ve_setenv ("LOGNAME", GdmUser, TRUE);
	        ve_setenv ("USER", GdmUser, TRUE);
	        ve_setenv ("USERNAME", GdmUser, TRUE);
        }
        if (pwent != NULL) {
		if (ve_string_empty (pwent->pw_dir)) {
			ve_setenv ("HOME", "/", TRUE);
			ve_setenv ("PWD", "/", TRUE);
			VE_IGNORE_EINTR (chdir ("/"));
		} else {
			ve_setenv ("HOME", pwent->pw_dir, TRUE);
			ve_setenv ("PWD", pwent->pw_dir, TRUE);
			VE_IGNORE_EINTR (chdir (pwent->pw_dir));
			if (errno != 0) {
				VE_IGNORE_EINTR (chdir ("/"));
				ve_setenv ("PWD", "/", TRUE);
			}
		}
	        ve_setenv ("SHELL", pwent->pw_shell, TRUE);
        } else {
	        ve_setenv ("HOME", "/", TRUE);
		ve_setenv ("PWD", "/", TRUE);
		VE_IGNORE_EINTR (chdir ("/"));
	        ve_setenv ("SHELL", "/bin/sh", TRUE);
        }

	if (set_parent)
		set_xnest_parent_stuff ();

	/* some env for use with the Pre and Post scripts */
	x_servers_file = gdm_make_filename (GdmServAuthDir,
					    d->name, ".Xservers");
	ve_setenv ("X_SERVERS", x_servers_file, TRUE);
	g_free (x_servers_file);
	if (d->type == TYPE_XDMCP)
		ve_setenv ("REMOTE_HOST", d->hostname, TRUE);

	/* Runs as root */
	if (GDM_AUTHFILE (d) != NULL)
		ve_setenv ("XAUTHORITY", GDM_AUTHFILE (d), TRUE);
	else
		ve_unsetenv ("XAUTHORITY");
        ve_setenv ("DISPLAY", d->name, TRUE);
	ve_setenv ("PATH", GdmRootPath, TRUE);
	ve_setenv ("RUNNING_UNDER_GDM", "true", TRUE);
	if ( ! ve_string_empty (d->theme_name))
		ve_setenv ("GDM_GTK_THEME", d->theme_name, TRUE);
	ve_unsetenv ("MAIL");
	argv = ve_split (script);
	VE_IGNORE_EINTR (execv (argv[0], argv));
	syslog (LOG_ERR, _("%s: Failed starting: %s"), "gdm_slave_exec_script",
		script);
	_exit (EXIT_SUCCESS);
	    
    case -1:
	if (set_parent)
		gdm_slave_whack_temp_auth_file ();
	g_free (script);
	syslog (LOG_ERR, _("%s: Can't fork script process!"), "gdm_slave_exec_script");
	return EXIT_SUCCESS;
	
    default:
	gdm_wait_for_extra (&status);

	if (set_parent)
		gdm_slave_whack_temp_auth_file ();

	g_free (script);

	if (WIFEXITED (status))
	    return WEXITSTATUS (status);
	else
	    return EXIT_SUCCESS;
    }
}

gboolean
gdm_slave_greeter_check_interruption (void)
{
	if (interrupted) {
		/* no longer interrupted */
		interrupted = FALSE;
		return TRUE;
	} else {
		return FALSE;
	}
}

gboolean
gdm_slave_action_pending (void)
{
	if (do_timed_login ||
	    do_configurator ||
	    do_restart_greeter)
		return FALSE;
	return TRUE;
}

/* The user name for automatic/timed login may be parameterized by 
   host/display. */

static gchar *
gdm_parse_enriched_login (const gchar *s, GdmDisplay *display)
{
    gchar cmd, in_buffer[20];
    GString *str;
    gint pipe1[2], in_buffer_len;  
    gchar **argv;
    pid_t pid;

    if (s == NULL)
	return(NULL);

    str = g_string_new (NULL);

    while (s[0] != '\0') {

	if (s[0] == '%' && s[1] != 0) {
		cmd = s[1];
		s++;

		switch (cmd) {

		case 'h': 
			g_string_append (str, display->hostname);
			break;

		case 'd': 
			g_string_append (str, display->name);
			break;

		case '%':
			g_string_append_c (str, '%');
			break;

		default:
			break;
		};
	} else {
		g_string_append_c (str, *s);
	}
	s++;
    }

    /* Sometimes it is not convenient to use the display or hostname as
       user name. A script may be used to generate the automatic/timed
       login name based on the display/host by ending the name with the
       pipe symbol '|'. */

    if(str->len > 0 && str->str[str->len - 1] == '|') {
      g_string_truncate(str, str->len - 1);
      if G_UNLIKELY (pipe (pipe1) < 0) {
        gdm_error (_("%s: Failed creating pipe"),
		   "gdm_parse_enriched_login");
      } else {
	pid = gdm_fork_extra ();

        switch (pid) {
	    
        case 0:
	    /* The child will write the username to stdout based on the DISPLAY
	       environment variable. */

            VE_IGNORE_EINTR (close (pipe1[0]));
            if G_LIKELY (pipe1[1] != STDOUT_FILENO)  {
	      VE_IGNORE_EINTR (dup2 (pipe1[1], STDOUT_FILENO));
	    }

	    closelog ();

	    gdm_close_all_descriptors (3 /* from */, pipe1[1] /* except */, -1 /* except2 */);

	    openlog ("gdm", LOG_PID, LOG_DAEMON);

	    /* runs as root */
	    if (GDM_AUTHFILE (display) != NULL)
		    ve_setenv ("XAUTHORITY", GDM_AUTHFILE (display), TRUE);
	    else
		    ve_unsetenv ("XAUTHORITY");
	    ve_setenv ("DISPLAY", display->name, TRUE);
	    if (display->type == TYPE_XDMCP)
		    ve_setenv ("REMOTE_HOST", display->hostname, TRUE);
	    ve_setenv ("PATH", GdmRootPath, TRUE);
	    ve_setenv ("SHELL", "/bin/sh", TRUE);
	    ve_setenv ("RUNNING_UNDER_GDM", "true", TRUE);
	    if ( ! ve_string_empty (d->theme_name))
		    ve_setenv ("GDM_GTK_THEME", d->theme_name, TRUE);
	    ve_unsetenv ("MAIL");

	    argv = ve_split (str->str);
	    VE_IGNORE_EINTR (execv (argv[0], argv));
	    gdm_error (_("%s: Failed executing: %s"),
		       "gdm_parse_enriched_login",
		       str->str);
	    _exit (EXIT_SUCCESS);
	    
        case -1:
	    gdm_error (_("%s: Can't fork script process!"),
		       "gdm_parse_enriched_login");
            VE_IGNORE_EINTR (close (pipe1[0]));
            VE_IGNORE_EINTR (close (pipe1[1]));
	    break;
	
        default:
	    /* The parent reads username from the pipe a chunk at a time */
            VE_IGNORE_EINTR (close (pipe1[1]));
            g_string_truncate (str, 0);
	    do {
		    VE_IGNORE_EINTR (in_buffer_len = read (pipe1[0], in_buffer,
							sizeof(in_buffer) - 1));
		    if (in_buffer_len > 0) {
			    in_buffer[in_buffer_len] = '\0';
			    g_string_append (str, in_buffer);
		    }
            } while (in_buffer_len > 0);

            if(str->len > 0 && str->str[str->len - 1] == '\n')
              g_string_truncate(str, str->len - 1);

            VE_IGNORE_EINTR (close(pipe1[0]));

	    gdm_wait_for_extra (NULL);
        }
      }
    }

    return g_string_free (str, FALSE);
}

static void
gdm_slave_handle_notify (const char *msg)
{
	int val;

	gdm_debug ("Handling slave notify: '%s'", msg);

	if (sscanf (msg, GDM_NOTIFY_ALLOWROOT " %d", &val) == 1) {
		GdmAllowRoot = val;
	} else if (sscanf (msg, GDM_NOTIFY_ALLOWREMOTEROOT " %d", &val) == 1) {
		GdmAllowRemoteRoot = val;
	} else if (sscanf (msg, GDM_NOTIFY_ALLOWREMOTEAUTOLOGIN " %d", &val) == 1) {
		GdmAllowRemoteAutoLogin = val;
	} else if (sscanf (msg, GDM_NOTIFY_SYSMENU " %d", &val) == 1) {
		GdmSystemMenu = val;
		if (d->greetpid > 1)
			kill (d->greetpid, SIGHUP);
	} else if (sscanf (msg, GDM_NOTIFY_CONFIG_AVAILABLE " %d", &val) == 1) {
		GdmConfigAvailable = val;
		if (d->greetpid > 1)
			kill (d->greetpid, SIGHUP);
	} else if (sscanf (msg, GDM_NOTIFY_CHOOSER_BUTTON " %d", &val) == 1) {
		GdmChooserButton = val;
		if (d->greetpid > 1)
			kill (d->greetpid, SIGHUP);
	} else if (sscanf (msg, GDM_NOTIFY_RETRYDELAY " %d", &val) == 1) {
		GdmRetryDelay = val;
	} else if (sscanf (msg, GDM_NOTIFY_DISALLOWTCP " %d", &val) == 1) {
		GdmDisallowTCP = val;
		remanage_asap = TRUE;
	} else if (strncmp (msg, GDM_NOTIFY_GREETER " ",
			    strlen (GDM_NOTIFY_GREETER) + 1) == 0) {
		g_free (GdmGreeter);
		GdmGreeter = g_strdup (&msg[strlen (GDM_NOTIFY_GREETER) + 1]);

		if (d->console) {
			do_restart_greeter = TRUE;
			if (restart_greeter_now) {
				; /* will get restarted later */
			} else if (d->type == TYPE_LOCAL) {
				/* FIXME: can't handle flexi servers like this
				 * without going all cranky */
				if ( ! d->logged_in) {
					gdm_slave_quick_exit (DISPLAY_REMANAGE);
				} else {
					remanage_asap = TRUE;
				}
			}
		}
	} else if (strncmp (msg, GDM_NOTIFY_REMOTEGREETER " ",
			    strlen (GDM_NOTIFY_REMOTEGREETER) + 1) == 0) {
		g_free (GdmRemoteGreeter);
		GdmRemoteGreeter = g_strdup
			(&msg[strlen (GDM_NOTIFY_REMOTEGREETER) + 1]);
		if ( ! d->console) {
			do_restart_greeter = TRUE;
			if (restart_greeter_now) {
				; /* will get restarted later */
			} else if (d->type == TYPE_XDMCP) {
				/* FIXME: can't handle flexi servers like this
				 * without going all cranky */
				if ( ! d->logged_in) {
					gdm_slave_quick_exit (DISPLAY_REMANAGE);
				} else {
					remanage_asap = TRUE;
				}
			}
		}
	} else if (strncmp (msg, GDM_NOTIFY_TIMED_LOGIN " ",
			    strlen (GDM_NOTIFY_TIMED_LOGIN) + 1) == 0) {
		do_restart_greeter = TRUE;
		/* FIXME: this is fairly nasty, we should handle this nicer */
		/* FIXME: can't handle flexi servers without going all cranky */
		if (d->type == TYPE_LOCAL || d->type == TYPE_XDMCP) {
			if ( ! d->logged_in) {
				gdm_slave_quick_exit (DISPLAY_REMANAGE);
			} else {
				remanage_asap = TRUE;
			}
		}
	} else if (sscanf (msg, GDM_NOTIFY_TIMED_LOGIN_DELAY " %d", &val) == 1) {
		GdmTimedLoginDelay = val;
		if (d->greetpid > 1)
			kill (d->greetpid, SIGHUP);
	} else if (strncmp (msg, GDM_NOTIFY_SOUND_ON_LOGIN_FILE " ",
			    strlen (GDM_NOTIFY_SOUND_ON_LOGIN_FILE) + 1) == 0) {
		g_free (GdmSoundOnLoginFile);
		GdmSoundOnLoginFile = g_strdup
			(&msg[strlen (GDM_NOTIFY_SOUND_ON_LOGIN_FILE) + 1]);
		if (d->greetpid > 1)
			kill (d->greetpid, SIGHUP);
	} else if (strncmp (msg, GDM_NOTIFY_GTK_MODULES_LIST " ",
			    strlen (GDM_NOTIFY_GTK_MODULES_LIST) + 1) == 0) {
		g_free (GdmGtkModulesList);
		GdmGtkModulesList = g_strdup
			(&msg[strlen (GDM_NOTIFY_GTK_MODULES_LIST) + 1]);

		if (GdmAddGtkModules) {
			do_restart_greeter = TRUE;
			if (restart_greeter_now) {
				; /* will get restarted later */
			} else if (d->type == TYPE_LOCAL) {
				/* FIXME: can't handle flexi servers like this
				 * without going all cranky */
				if ( ! d->logged_in) {
					gdm_slave_quick_exit (DISPLAY_REMANAGE);
				} else {
					remanage_asap = TRUE;
				}
			}
		}
	} else if (sscanf (msg, GDM_NOTIFY_ADD_GTK_MODULES " %d", &val) == 1) {
		GdmAddGtkModules = val;

		do_restart_greeter = TRUE;
		if (restart_greeter_now) {
			; /* will get restarted later */
		} else if (d->type == TYPE_LOCAL) {
			/* FIXME: can't handle flexi servers like this
			 * without going all cranky */
			if ( ! d->logged_in) {
				gdm_slave_quick_exit (DISPLAY_REMANAGE);
			} else {
				remanage_asap = TRUE;
			}
		}
	}
}

/* do cleanup but only if we are a slave, if we're not a slave, just
 * return FALSE */
gboolean
gdm_slave_final_cleanup (void)
{
	if (getpid () != d->slavepid)
		return FALSE;
	gdm_debug ("slave killing self");
	gdm_slave_term_handler (SIGTERM);
	return TRUE;
}

/* EOF */

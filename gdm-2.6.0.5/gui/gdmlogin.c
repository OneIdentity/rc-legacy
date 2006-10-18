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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <config.h>

#include <libgnome/libgnome.h>
#include <libgnomeui/libgnomeui.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <ctype.h>
#include <signal.h>
#include <dirent.h>
#include <locale.h>
#include <gdk/gdkx.h>
#include <X11/X.h>
#include <X11/Xlib.h>
#include <X11/XKBlib.h>
#include <pwd.h>
#include <sys/utsname.h>

#include <viciousui.h>

#include "gdm.h"
#include "gdmwm.h"
#include "gdmlanguages.h"
#include "gdmcommon.h"
#include "misc.h"

/* set the DOING_GDM_DEVELOPMENT env variable if you aren't running
 * within the protocol */
static gboolean DOING_GDM_DEVELOPMENT = FALSE;
static char *greeter_Welcome_key = GDM_KEY_WELCOME;

typedef struct _GdmLoginUser GdmLoginUser;
struct _GdmLoginUser {
    uid_t uid;
    char *login;
    char *homedir;
    char *gecos;
    GdkPixbuf *picture;
};

#define LAST_SESSION "Last"
#define LAST_LANGUAGE "Last"
#define DEFAULT_LANGUAGE "Default"
#define SESSION_NAME "SessionName"
#define GTK_KEY "gtk-2.0"

enum {
	GREETER_ULIST_ICON_COLUMN = 0,
	GREETER_ULIST_LABEL_COLUMN,
	GREETER_ULIST_LOGIN_COLUMN
};

static gboolean GdmAllowRoot;
static gboolean GdmAllowRemoteRoot;
static gboolean GdmBrowser;
static gboolean GdmDebug;
static gint  GdmIconMaxHeight;
static gint  GdmIconMaxWidth;
static gboolean GdmQuiver;
static gboolean GdmSystemMenu;
static gboolean GdmSystemMenuReal;
static gboolean GdmChooserButton;
static gboolean GdmChooserButtonReal;
static gchar *GdmHalt;
static gchar *GdmReboot;
static gchar *GdmSuspend;
static gboolean GdmConfigAvailable;
static gboolean GdmConfigAvailableReal;
static gchar *GdmConfigurator;
static gint GdmXineramaScreen;
static gchar *GdmLogo;
static gchar *GdmWelcome;
static gchar *GdmBackgroundProg;
static gboolean GdmRunBackgroundProgAlways;
static gchar *GdmBackgroundImage;
static gchar *GdmBackgroundColor;
static gboolean GdmBackgroundScaleToFit;
static gboolean GdmBackgroundRemoteOnlyColor;
static int GdmBackgroundType;
enum {
	GDM_BACKGROUND_NONE = 0,
	GDM_BACKGROUND_IMAGE = 1,
	GDM_BACKGROUND_COLOR = 2
};
static gchar *GdmGtkRC;
static gchar *GdmSessionDir;
static gchar *GdmDefaultSession;
static gchar *GdmLocaleFile;
static gchar *GdmExclude;
static int GdmMinimalUID;
static gchar *GdmGlobalFaceDir;
static gchar *GdmDefaultFace;
static gboolean GdmTimedLoginEnable;
static gboolean GdmUse24Clock;
static gchar *GdmTimedLogin;
static gint GdmTimedLoginDelay;
static gboolean GdmLockPosition;
static gboolean GdmSetPosition;
static gint GdmPositionX;
static gint GdmPositionY;
static gboolean GdmTitleBar;

static gboolean GdmAllowGtkThemeChange;
static char *GdmGtkThemesToAllow;
static char *GdmGtkTheme;

gboolean GdmSoundOnLogin;
gchar *GdmSoundOnLoginFile;
gchar *GdmSoundProgram;

static gboolean GdmShowGnomeFailsafeSession;
static gboolean GdmShowXtermFailsafeSession;
static gboolean GdmShowLastSession;

static gboolean GdmUseCirclesInEntry;
static gint GdmFlexiReapDelayMinutes;

/* FIXME: Should move everything to externs and move reading to gdmcommon.c */
gchar *GdmInfoMsgFile;
gchar *GdmInfoMsgFont;

static GtkWidget *login;
static GtkWidget *logo_frame = NULL;
static GtkWidget *logo_image = NULL;
static GtkWidget *table = NULL;
static GtkWidget *welcome;
static GtkWidget *label;
static GtkWidget *icon_button = NULL;
static GtkWidget *title_box = NULL;
static GtkWidget *clock_label = NULL;
static GtkWidget *entry;
static GtkWidget *ok_button;
static GtkWidget *msg;
static GtkWidget *err_box;
static guint err_box_clear_handler = 0;
static gboolean require_quarter = FALSE;
static GtkWidget *icon_win = NULL;
static GtkWidget *sessmenu;
static GtkWidget *langmenu;
static GtkTooltips *tooltips;
static GHashTable *sessnames;

static gboolean login_is_local = FALSE;
static gboolean used_defaults = FALSE;

static GtkWidget *browser;
static GtkTreeModel *browser_model;
static GdkPixbuf *defface;

/* Eew. Loads of global vars. It's hard to be event controlled while maintaining state */
static GSList *sessions = NULL;
static GSList *languages = NULL;
static GList *users = NULL;
static gint number_of_users = 0;
static gint size_of_users = 0;

static gchar *defsess = NULL;
static const gchar *cursess = NULL;
static const gchar *curlang = NULL;
static gchar *curuser = NULL;
static gchar *session = NULL;
static gchar *language = NULL;
static gint curdelay = 0;

static gboolean savesess = FALSE;
static gboolean savelang = FALSE;
static gint maxwidth = 0;
static gint maxheight = 0;

static pid_t backgroundpid = 0;

static guint timed_handler_id = 0;

static char *selected_browser_user = NULL;
static gboolean selecting_user = TRUE;

/* This is true if session dir doesn't exist or is whacked out
 * in some way or another */
static gboolean session_dir_whacked_out = FALSE;
static gboolean using_fallback_message = FALSE;

static void login_window_resize (gboolean force);

/*
 * Timed Login: Timer
 */

static gboolean
gdm_timer (gpointer data)
{
	curdelay --;
	if ( curdelay <= 0 ) {
		/* timed interruption */
		printf ("%c%c%c\n", STX, BEL, GDM_INTERRUPT_TIMED_LOGIN);
		fflush (stdout);
	} else if ((curdelay % 5) == 0) {
		gchar *autologin_msg = 
			g_strdup_printf (_("User %s will login in %d seconds"),
					 GdmTimedLogin, curdelay);
		gtk_label_set_text (GTK_LABEL (msg), autologin_msg);
		gtk_widget_show (GTK_WIDGET (msg));
		g_free (autologin_msg);
		login_window_resize (FALSE /* force */);
	}
	return TRUE;
}

/*
 * Timed Login: On GTK events, increase delay to
 * at least 30 seconds. Or the TimedLoginDelay,
 * whichever is higher
 */

static gboolean
gdm_timer_up_delay (GSignalInvocationHint *ihint,
		    guint	           n_param_values,
		    const GValue	  *param_values,
		    gpointer		   data)
{
	if (curdelay < 30)
		curdelay = 30;
	if (curdelay < GdmTimedLoginDelay)
		curdelay = GdmTimedLoginDelay;
	return TRUE;
}

/* The reaping stuff */
static time_t last_reap_delay = 0;

static gboolean
delay_reaping (GSignalInvocationHint *ihint,
	       guint	           n_param_values,
	       const GValue	  *param_values,
	       gpointer		   data)
{
	last_reap_delay = time (NULL);
	return TRUE;
}      

static gboolean
reap_flexiserver (gpointer data)
{
	if (GdmFlexiReapDelayMinutes > 0 &&
	    ((time (NULL) - last_reap_delay) / 60) > GdmFlexiReapDelayMinutes) {
		gdm_kill_thingies ();
		_exit (DISPLAY_REMANAGE);
	}
	return TRUE;
}


static gboolean
gdm_event (GSignalInvocationHint *ihint,
	   guint		n_param_values,
	   const GValue	       *param_values,
	   gpointer		data)
{
	GdkEvent *event;

	/* HAAAAAAAAAAAAAAAAACK */
	/* Since the user has not logged in yet and may have left/right
	 * mouse buttons switched, we just translate every right mouse click
	 * to a left mouse click */
	if (n_param_values != 2 ||
	    !G_VALUE_HOLDS (&param_values[1], GDK_TYPE_EVENT))
	  return FALSE;
	
	event = g_value_get_boxed (&param_values[1]);
	if ((event->type == GDK_BUTTON_PRESS ||
	     event->type == GDK_2BUTTON_PRESS ||
	     event->type == GDK_3BUTTON_PRESS ||
	     event->type == GDK_BUTTON_RELEASE)
	    && event->button.button == 3)
		event->button.button = 1;

	return TRUE;
}      

void
gdm_kill_thingies (void)
{
	pid_t pid = backgroundpid;

	backgroundpid = 0;
	if (pid > 0) {
		if (kill (pid, SIGTERM) == 0)
			waitpid (pid, NULL, 0);
	}
}


static void
gdm_login_done (int sig)
{
    gdm_kill_thingies ();
    _exit (EXIT_SUCCESS);
}

static void
set_screen_pos (GtkWidget *widget, int x, int y)
{
	int width, height;

	g_return_if_fail (widget != NULL);
	g_return_if_fail (GTK_IS_WIDGET (widget));

	gtk_window_get_size (GTK_WINDOW (widget), &width, &height);

	/* allow negative values, to be like standard X geometry ones */
	if (x < 0)
		x = gdm_wm_screen.width + x - width;
	if (y < 0)
		y = gdm_wm_screen.height + y - height;

	if (x < gdm_wm_screen.x)
		x = gdm_wm_screen.x;
	if (y < gdm_wm_screen.y)
		y = gdm_wm_screen.y;
	if (x > gdm_wm_screen.x + gdm_wm_screen.width - width)
		x = gdm_wm_screen.x + gdm_wm_screen.width - width;
	if (y > gdm_wm_screen.y + gdm_wm_screen.height - height)
		y = gdm_wm_screen.y + gdm_wm_screen.height - height;

	gtk_window_move (GTK_WINDOW (widget), x, y);
}

static guint set_pos_id = 0;

static gboolean
set_pos_idle (gpointer data)
{
	if (GdmSetPosition) {
		set_screen_pos (login, GdmPositionX, GdmPositionY);
	} else {
		gdm_wm_center_window (GTK_WINDOW (login));
	}
	set_pos_id = 0;
	return FALSE;
}

static void
login_window_resize (gboolean force)
{
	/* allow opt out if we don't really need
	 * a resize */
	if ( ! force) {
		GtkRequisition req;
		int width, height;

		gtk_window_get_size (GTK_WINDOW (login), &width, &height);
		gtk_widget_size_request (login, &req);

		if (req.width <= width && req.height <= height)
			return;
	}

	GTK_WINDOW (login)->need_default_size = TRUE;
	gtk_container_check_resize (GTK_CONTAINER (login));

	if (set_pos_id == 0)
		set_pos_id = g_idle_add (set_pos_idle, NULL);
}


typedef struct _CursorOffset {
	int x;
	int y;
} CursorOffset;

static gboolean
within_rect (GdkRectangle *rect, int x, int y)
{
	return
		x >= rect->x &&
		x <= rect->x + rect->width &&
		y >= rect->y &&
		y <= rect->y + rect->height;
}

/* switch to the xinerama screen where x,y are */
static void
set_screen_to_pos (int x, int y)
{
	if ( ! within_rect (&gdm_wm_screen, x, y)) {
		int i;
		/* If not within gdm_wm_screen boundaries,
		 * maybe we want to switch xinerama
		 * screen */
		for (i = 0; i < gdm_wm_screens; i++) {
			if (within_rect (&gdm_wm_allscreens[i], x, y)) {
				gdm_wm_set_screen (i);
				break;
			}
		}
	}
}


/* I *really* need to rewrite this crap */
static gchar *
gdm_parse_enriched_string (const char *pre, const gchar *s, const char *post)
{
    gchar hostbuf[1023] = "";
    gchar *hostname, *display;
    struct utsname name;
    GString *str;

    if (s == NULL)
	return(NULL);

    hostbuf[sizeof (hostbuf) - 1] = '\0';
    if (gethostname (hostbuf, sizeof (hostbuf) - 1) < 0)
	    hostname = g_strdup ("Gnome");
    else
	    hostname = g_strdup (hostbuf);

    display = g_strdup (g_getenv ("DISPLAY"));

    uname (&name);

    if (strlen (s) > 2048) {
	    char *buffer;
	    syslog (LOG_ERR, _("%s: String too long!"), "gdm_parse_enriched_string");
	    g_free (display);
	    buffer = g_strdup_printf (_("%sWelcome to %s%s"),
				      pre, name.nodename, post);
	    g_free (hostname);
	    return buffer;
    }

    str = g_string_new (pre);

    while (s[0] != '\0') {
	/* Backslash commands */
	if (s[0] == '\\' && s[1] != '\0') {
		char cmd = s[1];
		s++;
		switch (cmd) {
		case 'n':
			g_string_append_c (str, '\n');
			break;
		default:
			g_string_append_c (str, cmd);
		}
	/* Percent commands */
	} else if (s[0] == '%' && s[1] != 0) {
		char cmd = s[1];
		s++;

		switch (cmd) {
		case 'h': 
			g_string_append (str, hostname);
			break;

		case 'n':
			g_string_append (str, name.nodename);
			break;

		case 'd': 
			g_string_append (str, ve_sure_string (display));
			break;

		case 's':
			g_string_append (str, name.sysname);
			break;

		case 'r':
			g_string_append (str, name.release);
			break;

		case 'm':
			g_string_append (str, name.machine);
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

    g_string_append (str, post);

    g_free (display);
    g_free (hostname);

    return g_string_free (str, FALSE);
}

static pid_t
gdm_run_command (const char *command)
{
	pid_t pid;
	char **argv;

	pid = fork ();

	if G_UNLIKELY (pid == -1) {
		GtkWidget *dialog;
		/* We can't fork, that means we're pretty much up shit creek
		 * without a paddle. */
		dialog = ve_hig_dialog_new (NULL /* parent */,
					    GTK_DIALOG_MODAL /* flags */,
					    GTK_MESSAGE_ERROR,
					    GTK_BUTTONS_OK,
					    FALSE /* markup */,
					    _("Could not fork a new process!"),
					    "%s",
					    _("You likely won't be able to log "
					      "in either."));
		gtk_widget_show_all (dialog);
		gdm_wm_center_window (GTK_WINDOW (dialog));

		gtk_dialog_run (GTK_DIALOG (dialog));
		gtk_widget_destroy (dialog);
	} else if (pid == 0) {
		int i;

		/* close everything */

		for (i = 0; i < sysconf (_SC_OPEN_MAX); i++)
			close(i);

		/* No error checking here - if it's messed the best
		 * response is to ignore & try to continue */
		open("/dev/null", O_RDONLY); /* open stdin - fd 0 */
		open("/dev/null", O_RDWR); /* open stdout - fd 1 */
		open("/dev/null", O_RDWR); /* open stderr - fd 2 */

		argv = ve_split (command);
		execv (argv[0], argv);
		/*ingore errors, this is irrelevant */
		_exit (0);
	}

	return pid;
}

static void
gdm_run_gdmconfig (GtkWidget *w, gpointer data)
{
	/* we should be now fine for focusing new windows */
	gdm_wm_focus_new_windows (TRUE);

	/* configure interruption */
	printf ("%c%c%c\n", STX, BEL, GDM_INTERRUPT_CONFIGURE);
	fflush (stdout);
}

static void
gdm_login_reboot_handler (void)
{
	if (gdm_common_query (_("Are you sure you want to reboot the machine?"),
			     FALSE /* markup */,
			     _("_Reboot"), GTK_STOCK_CANCEL)) {
		closelog();

		gdm_kill_thingies ();
		_exit (DISPLAY_REBOOT);
	}
}


static void
gdm_login_halt_handler (void)
{
	if (gdm_common_query (_("Are you sure you want to shut down the machine?"),
			     FALSE /* markup */,
			     _("Shut _Down"), GTK_STOCK_CANCEL)) {
		closelog();

		gdm_kill_thingies ();
		_exit (DISPLAY_HALT);
	}
}

static void
gdm_login_use_chooser_handler (void)
{
	closelog();

	gdm_kill_thingies ();
	_exit (DISPLAY_RUN_CHOOSER);
}

static void
gdm_login_suspend_handler (void)
{
	if (gdm_common_query (_("Are you sure you want to suspend the machine?"),
			     FALSE /* markup */,
			     _("_Suspend"), GTK_STOCK_CANCEL)) {
		/* suspend interruption */
		printf ("%c%c%c\n", STX, BEL, GDM_INTERRUPT_SUSPEND);
		fflush (stdout);
	}
}

static void
gdm_theme_handler (GtkWidget *widget, gpointer data)
{
    const char *theme_name = (const char *)data;

    printf ("%c%c%c%s\n", STX, BEL, GDM_INTERRUPT_THEME, theme_name);
  
    fflush (stdout);

    gdm_set_theme (theme_name);

    login_window_resize (FALSE);
    gdm_wm_center_window (GTK_WINDOW (login));
}

static void 
gdm_login_parse_config (void)
{
    struct stat unused;
    VeConfig *config;
	
    if G_UNLIKELY (stat (GDM_CONFIG_FILE, &unused) == -1) {
	syslog (LOG_ERR, _("%s: No configuration file: %s. Using defaults."), 
		"gdm_login_parse_config", GDM_CONFIG_FILE);
	used_defaults = TRUE;
    }

    if (ve_string_empty (g_getenv ("GDM_IS_LOCAL"))) {
	    greeter_Welcome_key = GDM_KEY_REMOTEWELCOME;
    } else {
	    greeter_Welcome_key = GDM_KEY_WELCOME;
    }

    config = ve_config_get (GDM_CONFIG_FILE);

    GdmAllowRoot = ve_config_get_bool (config, GDM_KEY_ALLOWROOT);
    GdmAllowRemoteRoot = ve_config_get_bool (config, GDM_KEY_ALLOWREMOTEROOT);
    GdmBrowser = ve_config_get_bool (config, GDM_KEY_BROWSER);
    GdmLogo = ve_config_get_string (config, GDM_KEY_LOGO);
    GdmQuiver = ve_config_get_bool (config, GDM_KEY_QUIVER);
    GdmSystemMenuReal = GdmSystemMenu = ve_config_get_bool (config, GDM_KEY_SYSMENU);
    GdmChooserButtonReal = GdmChooserButton = ve_config_get_bool (config, GDM_KEY_CHOOSER_BUTTON);
    GdmHalt = ve_config_get_string (config, GDM_KEY_HALT);
    GdmReboot = ve_config_get_string (config, GDM_KEY_REBOOT);
    GdmSuspend = ve_config_get_string (config, GDM_KEY_SUSPEND);
    GdmConfigAvailableReal = GdmConfigAvailable = ve_config_get_bool (config, GDM_KEY_CONFIG_AVAILABLE);
    GdmConfigurator = ve_config_get_string (config, GDM_KEY_CONFIGURATOR);
    GdmInfoMsgFile = ve_config_get_string (config, GDM_KEY_INFO_MSG_FILE);
    GdmInfoMsgFont = ve_config_get_string (config, GDM_KEY_INFO_MSG_FONT);
    GdmTitleBar = ve_config_get_bool (config, GDM_KEY_TITLE_BAR);
    GdmLocaleFile = ve_config_get_string (config, GDM_KEY_LOCFILE);
    GdmSessionDir = ve_config_get_string (config, GDM_KEY_SESSDIR);
    GdmDefaultSession = ve_config_get_string (config, GDM_KEY_DEFAULTSESSION);
    GdmWelcome = ve_config_get_translated_string (config, greeter_Welcome_key);
    /* A hack! */
    if (strcmp (ve_sure_string (GdmWelcome), "Welcome") == 0) {
	    g_free (GdmWelcome);
	    GdmWelcome = g_strdup (_("Welcome"));
    } else if (strcmp (ve_sure_string (GdmWelcome), "Welcome to %n") == 0) {
	    g_free (GdmWelcome);
	    GdmWelcome = g_strdup (_("Welcome to %n"));
    }
    GdmBackgroundProg = ve_config_get_string (config, GDM_KEY_BACKGROUNDPROG);
    GdmRunBackgroundProgAlways = ve_config_get_bool (config, GDM_KEY_RUNBACKGROUNDPROGALWAYS);
    GdmBackgroundImage = ve_config_get_string (config, GDM_KEY_BACKGROUNDIMAGE);
    GdmBackgroundColor = ve_config_get_string (config, GDM_KEY_BACKGROUNDCOLOR);
    GdmBackgroundType = ve_config_get_int (config, GDM_KEY_BACKGROUNDTYPE);
    GdmBackgroundScaleToFit = ve_config_get_bool (config, GDM_KEY_BACKGROUNDSCALETOFIT);
    GdmBackgroundRemoteOnlyColor = ve_config_get_bool (config, GDM_KEY_BACKGROUNDREMOTEONLYCOLOR);
    GdmGtkRC = ve_config_get_string (config, GDM_KEY_GTKRC);
    GdmExclude = ve_config_get_string (config, GDM_KEY_EXCLUDE);
    GdmMinimalUID = ve_config_get_int (config, GDM_KEY_MINIMALUID);
    GdmGlobalFaceDir = ve_config_get_string (config, GDM_KEY_FACEDIR);
    GdmDefaultFace = ve_config_get_string (config, GDM_KEY_FACE);
    GdmDebug = ve_config_get_bool (config, GDM_KEY_DEBUG);
    GdmIconMaxWidth = ve_config_get_int (config, GDM_KEY_ICONWIDTH);
    GdmIconMaxHeight = ve_config_get_int (config, GDM_KEY_ICONHEIGHT);
    GdmXineramaScreen = ve_config_get_int (config, GDM_KEY_XINERAMASCREEN);
    GdmUseCirclesInEntry = ve_config_get_bool (config, GDM_KEY_ENTRY_CIRCLES);
    GdmLockPosition = ve_config_get_bool (config, GDM_KEY_LOCK_POSITION);
    GdmSetPosition = ve_config_get_bool (config, GDM_KEY_SET_POSITION);
    GdmPositionX = ve_config_get_int (config, GDM_KEY_POSITIONX);
    GdmPositionY = ve_config_get_int (config, GDM_KEY_POSITIONY);

    GdmAllowGtkThemeChange = ve_config_get_bool (config, GDM_KEY_ALLOW_GTK_THEME_CHANGE);
    GdmGtkThemesToAllow = ve_config_get_string (config, GDM_KEY_GTK_THEMES_TO_ALLOW);
    GdmGtkTheme = ve_config_get_string (config, GDM_KEY_GTK_THEME);

    GdmShowXtermFailsafeSession = ve_config_get_bool (config, GDM_KEY_SHOW_XTERM_FAILSAFE);
    GdmShowGnomeFailsafeSession = ve_config_get_bool (config, GDM_KEY_SHOW_GNOME_FAILSAFE);
    GdmShowLastSession = ve_config_get_bool (config, GDM_KEY_SHOW_LAST_SESSION);
    
    GdmTimedLoginEnable = ve_config_get_bool (config, GDM_KEY_TIMED_LOGIN_ENABLE);

    /* Note: TimedLogin here is not gotten out of the config
     * but from the daemon since it's been munged on by the daemon a bit
     * already maybe */
    if (GdmTimedLoginEnable) {
	    GdmTimedLogin = g_strdup (g_getenv("GDM_TIMED_LOGIN_OK"));
            if (ve_string_empty (GdmTimedLogin)) {
	      g_free (GdmTimedLogin);
	      GdmTimedLogin = NULL;
	    }

	    GdmTimedLoginDelay =
		    ve_config_get_int (config, GDM_KEY_TIMED_LOGIN_DELAY);
	    if (GdmTimedLoginDelay < 5) {
		    syslog (LOG_WARNING,
			    _("TimedLoginDelay was less than 5.  I'll just use 5."));
		    GdmTimedLoginDelay = 5;
	    }
    } else {
	    GdmTimedLogin = NULL;
	    GdmTimedLoginDelay = 5;
    }
  
    GdmFlexiReapDelayMinutes = ve_config_get_int (config, GDM_KEY_FLEXI_REAP_DELAY_MINUTES);
    GdmUse24Clock = ve_config_get_bool (config, GDM_KEY_USE_24_CLOCK);

    GdmSoundOnLogin = ve_config_get_bool (config, GDM_KEY_SOUND_ON_LOGIN);
    GdmSoundOnLoginFile = ve_config_get_string (config, GDM_KEY_SOUND_ON_LOGIN_FILE);
    GdmSoundProgram = ve_config_get_string (config, GDM_KEY_SOUND_PROGRAM);

    if (GdmIconMaxWidth < 0) GdmIconMaxWidth = 128;
    if (GdmIconMaxHeight < 0) GdmIconMaxHeight = 128;
    if (GdmXineramaScreen < 0) GdmXineramaScreen = 0;

    /* Disable System menu on non-local displays */
    if (ve_string_empty (g_getenv ("GDM_IS_LOCAL"))) {
	    GdmSystemMenuReal = FALSE;
	    GdmConfigAvailableReal = FALSE;
	    GdmChooserButtonReal = FALSE;
	    if (GdmBackgroundRemoteOnlyColor &&
		GdmBackgroundType == GDM_BACKGROUND_IMAGE)
		    GdmBackgroundType = GDM_BACKGROUND_COLOR;
	    if (GdmBackgroundRemoteOnlyColor &&
		! ve_string_empty (GdmBackgroundProg)) {
		    g_free (GdmBackgroundProg);
		    GdmBackgroundProg = NULL;
	    }
	    login_is_local = FALSE;
    } else {
	    login_is_local = TRUE;
    }
}


static gboolean 
gdm_login_list_lookup (GSList *l, const gchar *data)
{
    GSList *list = l;

    if (list == NULL || data == NULL)
	return FALSE;

    /* FIXME: Hack, will support these builtin types later */
    if (strcmp (data, GDM_SESSION_DEFAULT ".desktop") == 0 ||
	strcmp (data, GDM_SESSION_CUSTOM ".desktop") == 0 ||
	strcmp (data, GDM_SESSION_FAILSAFE ".desktop") == 0) {
	    return TRUE;
    }

    while (list) {

	if (strcmp (list->data, data) == 0)
	    return TRUE;
	
	list = list->next;
    }

    return FALSE;
}

static const char *
session_name (const char *name)
{
	const char *nm;

	/* eek */
	if G_UNLIKELY (name == NULL)
		return "(null)";

	nm = g_hash_table_lookup (sessnames, name);
	if (nm != NULL)
		return nm;
	else
		return name;
}


static void
gdm_login_session_lookup (const gchar* savedsess)
{
    /* Don't save session unless told otherwise */
    savesess = FALSE;

    gtk_widget_set_sensitive (GTK_WIDGET (sessmenu), FALSE);

    /* Previously saved session not found in ~user/.gnome2/gdm */
    if ( ! (savedsess != NULL &&
	    strcmp ("(null)", savedsess) != 0 &&
	    savedsess[0] != '\0')) {
	    /* If "Last" is chosen run Default,
	     * else run user's current selection */
	    g_free (session);
	    if (cursess == NULL || strcmp (cursess, LAST_SESSION) == 0)
		    session = g_strdup (defsess);
	    else
		    session = g_strdup (cursess);

	    savesess = TRUE;
	    return;
    }

    /* If "Last" session is selected */
    if (cursess == NULL ||
	strcmp (cursess, LAST_SESSION) == 0) { 
	g_free (session);
	session = g_strdup (savedsess);

	/* Check if user's saved session exists on this box */
	if (!gdm_login_list_lookup (sessions, session)) {
	    gchar *msg;

	    g_free (session);
	    session = g_strdup (defsess);
            msg = g_strdup_printf (_("Your preferred session type %s is not "
				     "installed on this machine.\n"
                                     "Do you wish to make %s the default for "
				     "future sessions?"),
                                   session_name (savedsess),
                                   session_name (defsess));	    
	    savesess = gdm_common_query (msg, FALSE /* markup */, _("Make _Default"), _("Just _Log In"));
	    g_free (msg);
	}
    }
    /* One of the other available session types is selected */
    else { 
	g_free (session);
	session = g_strdup (cursess);

	/* User's saved session is not the chosen one */
	if (strcmp (session, GDM_SESSION_FAILSAFE_GNOME) == 0 ||
	    strcmp (session, GDM_SESSION_FAILSAFE_XTERM) == 0 ||
	    g_ascii_strcasecmp (session, GDM_SESSION_FAILSAFE ".desktop") == 0 ||
	    g_ascii_strcasecmp (session, GDM_SESSION_FAILSAFE) == 0) {
		savesess = FALSE;
	} else if (strcmp (savedsess, session) != 0) {
		gchar *msg = NULL;

                if (GdmShowLastSession) {
                        msg = g_strdup_printf (_("You have chosen %s for this "
                                                 "session, but your default "
                                                 "setting is %s.\nDo you wish "
                                                 "to make %s the default for "
                                                 "future sessions?"),
                                               session_name (session),
                                               session_name (savedsess),
                                               session_name (session));
			savesess = gdm_common_query (msg, FALSE /* markup */, _("Make _Default"), _("Just For _This Session"));
                } else if (strcmp (session, defsess) != 0 &&
			   strcmp (session, savedsess) != 0 &&
                           strcmp (session, LAST_SESSION) != 0) {
                        /* if !GdmShowLastSession then our saved session is
                         * irrelevant, we are in "switchdesk mode"
                         * and the relevant thing is the saved session
                         * in .Xclients
                         */
			if (access ("/usr/bin/switchdesk", F_OK) == 0) {
				msg = g_strdup_printf (_("You have chosen %s for this "
							 "session.\nIf you wish to make %s "
							 "the default for future sessions,\n"
							 "run the 'switchdesk' utility\n"
							 "(System->Desktop Switching Tool from "
							 "the panel menu)."),
						       session_name (session),
						       session_name (session));
				gdm_common_message (msg);
			}
			savesess = FALSE;
                }
		g_free (msg);
	}
    }
}


static void
gdm_login_language_lookup (const gchar* savedlang)
{
    /* Don't save language unless told otherwise */
    savelang = FALSE;

    if (langmenu != NULL)
	    gtk_widget_set_sensitive (GTK_WIDGET (langmenu), FALSE);

    if (savedlang == NULL)
	    savedlang = "";

    /* If a different language is selected */
    if (curlang != NULL && strcmp (curlang, LAST_LANGUAGE) != 0) {
        g_free (language);
	if (strcmp (curlang, DEFAULT_LANGUAGE) == 0)
		language = g_strdup ("");
	else
		language = g_strdup (curlang);

	/* User's saved language is not the chosen one */
	if (strcmp (savedlang, language) != 0) {
	    gchar *msg;
	    char *curname, *savedname;

	    if (strcmp (curlang, DEFAULT_LANGUAGE) == 0) {
		    curname = g_strdup (_("System Default"));
	    } else {
		    curname = gdm_lang_name (curlang,
					     FALSE /* never_encoding */,
					     TRUE /* no_group */,
					     TRUE /* untranslated */,
					     TRUE /* markup */);
	    }
	    if (strcmp (savedlang, "") == 0) {
		    savedname = g_strdup (_("System Default"));
	    } else {
		    savedname = gdm_lang_name (savedlang,
					       FALSE /* never_encoding */,
					       TRUE /* no_group */,
					       TRUE /* untranslated */,
					       TRUE /* markup */);
	    }

	    msg = g_strdup_printf (_("You have chosen %s for this session, but your default setting is "
				     "%s.\nDo you wish to make %s the default for future sessions?"),
				   curname, savedname, curname);
	    g_free (curname);
	    g_free (savedname);

	    savelang = gdm_common_query (msg, TRUE /* markup */, _("Make _Default"), _("Just For _This Session"));
	    g_free (msg);
	}
    } else {
	g_free (language);
	language = g_strdup (savedlang);
    }
}

static int dance_handler = 0;

static gboolean
dance (gpointer data)
{
	static double t1 = 0.0, t2 = 0.0;
	double xm, ym;
	int x, y;
	static int width = -1;
	static int height = -1;

	if (width == -1)
		width = gdm_wm_screen.width;
	if (height == -1)
		height = gdm_wm_screen.height;

	if (login == NULL ||
	    login->window == NULL) {
		dance_handler = 0;
		return FALSE;
	}

	xm = cos (2.31 * t1);
	ym = sin (1.03 * t2);

	t1 += 0.03 + (rand () % 10) / 500.0;
	t2 += 0.03 + (rand () % 10) / 500.0;

	x = gdm_wm_screen.x + (width / 2) + (width / 5) * xm;
	y = gdm_wm_screen.y + (height / 2) + (height / 5) * ym;

	set_screen_pos (login,
			x - login->allocation.width / 2,
			y - login->allocation.height / 2);

	return TRUE;
}

static gboolean
evil (const char *user)
{
	static gboolean old_lock;

	if (dance_handler == 0 &&
	    /* do not translate */
	    strcmp (user, "Start Dancing") == 0) {
		gdm_common_setup_cursor (GDK_UMBRELLA);
		dance_handler = g_timeout_add (50, dance, NULL);
		old_lock = GdmLockPosition;
		GdmLockPosition = TRUE;
		gtk_entry_set_text (GTK_ENTRY (entry), "");
		return TRUE;
	} else if (dance_handler != 0 &&
		   /* do not translate */
		   strcmp (user, "Stop Dancing") == 0) {
		gdm_common_setup_cursor (GDK_LEFT_PTR);
		g_source_remove (dance_handler);
		dance_handler = 0;
		GdmLockPosition = old_lock;
		gdm_wm_center_window (GTK_WINDOW (login));
		gtk_entry_set_text (GTK_ENTRY (entry), "");
		return TRUE;
				 /* do not translate */
	} else if (strcmp (user, "Gimme Random Cursor") == 0) {
		gdm_common_setup_cursor (((rand () >> 3) % (GDK_LAST_CURSOR/2)) * 2);
		gtk_entry_set_text (GTK_ENTRY (entry), "");
		return TRUE;
				 /* do not translate */
	} else if (strcmp (user, "Require Quater") == 0 ||
		   strcmp (user, "Require Quarter") == 0) {
		/* btw, note that I misspelled quarter before and
		 * thus this checks for Quater as well as Quarter to
		 * keep compatibility which is obviously important for
		 * something like this */
		require_quarter = TRUE;
		gtk_entry_set_text (GTK_ENTRY (entry), "");
		return TRUE;
	}

	return FALSE;
}

static void
gdm_login_enter (GtkWidget *entry)
{
	const char *login_string;
	const char *str;
	char *tmp;

	if (entry == NULL)
		return;

	gtk_widget_set_sensitive (entry, FALSE);
	gtk_widget_set_sensitive (ok_button, FALSE);

	login_string = gtk_entry_get_text (GTK_ENTRY (entry));

	str = gtk_label_get_text (GTK_LABEL (label));
	if (str != NULL &&
	    (strcmp (str, _("Username:")) == 0 ||
	     strcmp (str, _("_Username:")) == 0) &&
	    /* If in timed login mode, and if this is the login
	     * entry.  Then an enter by itself is sort of like I want to
	     * log in as the timed user "damn it".  */
	    ve_string_empty (login_string) &&
	    timed_handler_id != 0) {
		/* timed interruption */
		printf ("%c%c%c\n", STX, BEL, GDM_INTERRUPT_TIMED_LOGIN);
		fflush (stdout);
		return;
	}

	if (str != NULL &&
	    (strcmp (str, _("Username:")) == 0 ||
	     strcmp (str, _("_Username:")) == 0) &&
	    /* evilness */
	    evil (login_string)) {
		/* obviously being 100% reliable is not an issue for
		   this test */
		gtk_widget_set_sensitive (entry, TRUE);
		gtk_widget_set_sensitive (ok_button, TRUE);
		gtk_widget_grab_focus (entry);	
		gtk_window_set_focus (GTK_WINDOW (login), entry);	
		return;
	}

	/* clear the err_box */
	if (err_box_clear_handler > 0)
		g_source_remove (err_box_clear_handler);
	err_box_clear_handler = 0;
	gtk_label_set_text (GTK_LABEL (err_box), "");

	tmp = ve_locale_from_utf8 (gtk_entry_get_text (GTK_ENTRY (entry)));
	printf ("%c%s\n", STX, gtk_entry_get_text (GTK_ENTRY (entry)));
	fflush (stdout);
	g_free (tmp);
}

static void
gdm_login_ok_button_press (GtkButton *button, GtkWidget *entry)
{
	gdm_login_enter (entry);
}

static gboolean
gdm_login_focus_in (GtkWidget *widget, GdkEventFocus *event)
{
	if (title_box != NULL)
		gtk_widget_set_state (title_box, GTK_STATE_SELECTED);

	if (icon_button != NULL)
		gtk_widget_set_state (icon_button, GTK_STATE_NORMAL);

	return FALSE;
}

static gboolean
gdm_login_focus_out (GtkWidget *widget, GdkEventFocus *event)
{
	if (title_box != NULL)
		gtk_widget_set_state (title_box, GTK_STATE_NORMAL);

	return FALSE;
}

static void 
gdm_login_session_handler (GtkWidget *widget) 
{
    gchar *s;

    cursess = g_object_get_data (G_OBJECT (widget), SESSION_NAME);

    s = g_strdup_printf (_("%s session selected"), session_name (cursess));

    gtk_label_set_text (GTK_LABEL (msg), s);
    g_free (s);

    login_window_resize (FALSE /* force */);
}


static void 
gdm_login_session_init (GtkWidget *menu)
{
    GSList *sessgrp = NULL;
    GtkWidget *item;
    DIR *sessdir;
    struct dirent *dent;
    gboolean searching_for_default = TRUE;
    int num = 1;
    int i;
    char **vec;
    gboolean some_dir_exists = FALSE;

    cursess = NULL;
    
    if (GdmShowLastSession) {
            cursess = LAST_SESSION;
            item = gtk_radio_menu_item_new_with_mnemonic (NULL, _("_Last"));
            g_object_set_data (G_OBJECT (item),
			       SESSION_NAME,
			       LAST_SESSION);
            sessgrp = gtk_radio_menu_item_get_group (GTK_RADIO_MENU_ITEM (item));
            gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
            g_signal_connect (G_OBJECT (item), "activate",
			      G_CALLBACK (gdm_login_session_handler),
			      NULL);
            gtk_widget_show (GTK_WIDGET (item));
            gtk_tooltips_set_tip (tooltips, GTK_WIDGET (item),
                                  _("Log in using the session that you have used "
                                    "last time you logged in"),
                                  NULL);
      
            item = gtk_menu_item_new();
            gtk_widget_set_sensitive (item, FALSE);
            gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
            gtk_widget_show (GTK_WIDGET (item));
    }

    sessnames = g_hash_table_new (g_str_hash, g_str_equal);
    g_hash_table_insert (sessnames, GDM_SESSION_FAILSAFE_GNOME, _("Failsafe Gnome"));
    g_hash_table_insert (sessnames, GDM_SESSION_FAILSAFE_XTERM, _("Failsafe xterm"));

    vec = g_strsplit (GdmSessionDir, ":", -1);
    for (i = 0; vec != NULL && vec[i] != NULL; i++) {
	    const char *dir = vec[i];

	    /* Check that session dir is readable */
	    if G_UNLIKELY (dir == NULL || access (dir, R_OK|X_OK) != 0)
		    continue;

	    some_dir_exists = TRUE;

	    /* Read directory entries in session dir */
	    sessdir = opendir (dir);

	    if G_LIKELY (sessdir != NULL)
		    dent = readdir (sessdir);
	    else
		    dent = NULL;

	    while (dent != NULL) {
		    VeConfig *cfg;
		    char *exec;
		    char *name;
		    char *comment;
		    char *s;
		    char *label;
		    char *tryexec;
		    char *ext;

		    /* ignore everything but the .desktop files */
		    ext = strstr (dent->d_name, ".desktop");
		    if (ext == NULL ||
			strcmp (ext, ".desktop") != 0) {
			    dent = readdir (sessdir);
			    continue;
		    }

		    /* already found this session, ignore */
		    if (g_hash_table_lookup (sessnames, dent->d_name) != NULL) {
			    dent = readdir (sessdir);
			    continue;
		    }

		    s = g_strconcat (dir, "/", dent->d_name, NULL);
		    cfg = ve_config_new (s);
		    g_free (s);

		    if (ve_config_get_bool (cfg, "Desktop Entry/Hidden=false")) {
			    g_hash_table_insert (sessnames, g_strdup (dent->d_name), "foo");
			    ve_config_destroy (cfg);
			    dent = readdir (sessdir);
			    continue;
		    }

		    tryexec = ve_config_get_string (cfg, "Desktop Entry/TryExec");
		    if ( ! ve_string_empty (tryexec)) {
			    char *full = g_find_program_in_path (tryexec);
			    if (full == NULL) {
				    g_hash_table_insert (sessnames, g_strdup (dent->d_name), "foo");
				    g_free (tryexec);
				    ve_config_destroy (cfg);
				    dent = readdir (sessdir);
				    continue;
			    }
			    g_free (full);
		    }
		    g_free (tryexec);

		    exec = ve_config_get_string (cfg, "Desktop Entry/Exec");
		    name = ve_config_get_translated_string (cfg, "Desktop Entry/Name");
		    comment = ve_config_get_translated_string (cfg, "Desktop Entry/Comment");

		    ve_config_destroy (cfg);

		    if G_UNLIKELY (ve_string_empty (exec) || ve_string_empty (name)) {
			    g_hash_table_insert (sessnames, g_strdup (dent->d_name), "foo");
			    g_free (exec);
			    g_free (name);
			    g_free (comment);
			    dent = readdir (sessdir);
			    continue;
		    }

		    if (num < 10)
			    label = g_strdup_printf ("_%d. %s", num, name);
		    else
			    label = g_strdup (name);
		    num ++;

		    item = gtk_radio_menu_item_new_with_mnemonic (sessgrp, label);
		    g_free (label);
		    g_object_set_data_full (G_OBJECT (item),
					    SESSION_NAME,
					    g_strdup (dent->d_name),
					    (GDestroyNotify) g_free);

		    if ( ! ve_string_empty (comment))
			    gtk_tooltips_set_tip
				    (tooltips, GTK_WIDGET (item), comment, NULL);

		    sessgrp = gtk_radio_menu_item_get_group (GTK_RADIO_MENU_ITEM (item));
		    sessions = g_slist_append (sessions, g_strdup (dent->d_name));
		    gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
		    g_signal_connect (G_OBJECT (item), "activate",
				      G_CALLBACK (gdm_login_session_handler),
				      NULL);
		    gtk_widget_show (GTK_WIDGET (item));

		    /* if we found the default session */
		    if ( ! ve_string_empty (GdmDefaultSession) &&
			 strcmp (dent->d_name, GdmDefaultSession) == 0) {
			    g_free (defsess);
			    defsess = g_strdup (dent->d_name);
			    searching_for_default = FALSE;
		    }

		    /* if there is a session called Default */
		    if (searching_for_default &&
			g_ascii_strcasecmp (dent->d_name, "default.desktop") == 0) {
			    g_free (defsess);
			    defsess = g_strdup (dent->d_name);
		    }

		    if (searching_for_default &&
			g_ascii_strcasecmp (dent->d_name, "gnome.desktop") == 0) {
			    /* Just in case there is no default session and
			     * no default link, make gnome the default */
			    if (defsess == NULL)
				    defsess = g_strdup (dent->d_name);

		    }

		    g_hash_table_insert (sessnames, g_strdup (dent->d_name), name);

		    g_free (exec);
		    g_free (comment);

		    dent = readdir (sessdir);
	    }

	    if G_LIKELY (sessdir != NULL)
		    closedir (sessdir);
    }

    g_strfreev (vec);

    /* Check that session dir is readable */
    if G_UNLIKELY ( ! some_dir_exists) {
	syslog (LOG_ERR, _("%s: Session directory %s not found!"), "gdm_login_session_init", ve_sure_string (GdmSessionDir));
	GdmShowXtermFailsafeSession = TRUE;
	session_dir_whacked_out = TRUE;
    }

    if G_UNLIKELY (sessions == NULL) {
	    syslog (LOG_WARNING, _("Yaikes, nothing found in the session directory."));
	    session_dir_whacked_out = TRUE;
	    GdmShowXtermFailsafeSession = TRUE;

	    defsess = g_strdup (GDM_SESSION_FAILSAFE_GNOME);
    }

    if (GdmShowGnomeFailsafeSession) {
            /* For translators:  This is the failsafe login when the user
             * can't login otherwise */
            item = gtk_radio_menu_item_new_with_mnemonic (sessgrp,
							  _("Failsafe _Gnome"));
            gtk_tooltips_set_tip (tooltips, GTK_WIDGET (item),
                                  _("This is a failsafe session that will log you "
                                    "into GNOME.  No startup scripts will be read "
                                    "and it is only to be used when you can't log "
                                    "in otherwise.  GNOME will use the 'Default' "
                                    "session."),
                                  NULL);
            g_object_set_data (G_OBJECT (item),
			       SESSION_NAME, GDM_SESSION_FAILSAFE_GNOME);

            sessgrp = gtk_radio_menu_item_get_group (GTK_RADIO_MENU_ITEM (item));
            sessions = g_slist_append (sessions,
                                       g_strdup (GDM_SESSION_FAILSAFE_GNOME));
            gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
            g_signal_connect (G_OBJECT (item), "activate",
			      G_CALLBACK (gdm_login_session_handler),
			      NULL);
            gtk_widget_show (GTK_WIDGET (item));
    }

    if (GdmShowXtermFailsafeSession) {
            /* For translators:  This is the failsafe login when the user
             * can't login otherwise */
	    item = gtk_radio_menu_item_new_with_mnemonic (sessgrp,
							  _("Failsafe _Terminal"));
            gtk_tooltips_set_tip (tooltips, GTK_WIDGET (item),
                                  _("This is a failsafe session that will log you "
                                    "into a terminal.  No startup scripts will be read "
                                    "and it is only to be used when you can't log "
                                    "in otherwise.  To exit the terminal, "
                                    "type 'exit'."),
                                  NULL);
            g_object_set_data (G_OBJECT (item),
			       SESSION_NAME, GDM_SESSION_FAILSAFE_XTERM);

            sessgrp = gtk_radio_menu_item_get_group (GTK_RADIO_MENU_ITEM (item));
            sessions = g_slist_append (sessions,
                                       g_strdup (GDM_SESSION_FAILSAFE_XTERM));
            gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
            g_signal_connect (G_OBJECT (item), "activate",
			      G_CALLBACK (gdm_login_session_handler),
			      NULL);
            gtk_widget_show (GTK_WIDGET (item));
    }
                    
    if G_UNLIKELY (defsess == NULL) {
	    defsess = g_strdup (GDM_SESSION_FAILSAFE_GNOME);
	    syslog (LOG_WARNING, _("No default session link found. Using Failsafe GNOME.\n"));
    }
    
    if (cursess == NULL)
            cursess = defsess;

    /* Select the proper session */
    {
            GSList *tmp;
            
            tmp = sessgrp;
            while (tmp != NULL) {
                    GtkWidget *w = tmp->data;
                    const char *n;

                    n = g_object_get_data (G_OBJECT (w), SESSION_NAME);
                    
                    if (n && strcmp (n, cursess) == 0) {
                            gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM (w),
                                                            TRUE);
                            break;
                    }
                    
                    tmp = tmp->next;
            }
    }
}


static void 
gdm_login_language_handler (GtkWidget *widget) 
{
    gchar *s;
    char *name;

    if (!widget)
	return;

    curlang = g_object_get_data (G_OBJECT (widget), "Language");
    name = gdm_lang_name (curlang,
			  FALSE /* never_encoding */,
			  TRUE /* no_group */,
			  TRUE /* untranslated */,
			  TRUE /* makrup */);
    s = g_strdup_printf (_("%s language selected"), name);
    g_free (name);
    gtk_label_set_markup (GTK_LABEL (msg), s);
    g_free (s);

    login_window_resize (FALSE /* force */);
}


static GtkWidget *
gdm_login_language_menu_new (void)
{
    GtkWidget *menu;
    GtkWidget *item, *ammenu, *nzmenu, *omenu;
    GList *langlist, *li;
    gboolean has_other_locale = FALSE;
    GtkWidget *other_menu;
    const char *g1;
    const char *g2;

    langlist = gdm_lang_read_locale_file (GdmLocaleFile);

    if (langlist == NULL)
	    return NULL;

    menu = gtk_menu_new ();

    curlang = LAST_LANGUAGE;

    item = gtk_radio_menu_item_new_with_mnemonic (NULL, _("_Last"));
    languages = gtk_radio_menu_item_get_group (GTK_RADIO_MENU_ITEM (item));
    gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
    g_signal_connect (G_OBJECT (item), "activate", 
		      G_CALLBACK (gdm_login_language_handler), 
		      NULL);
    gtk_widget_show (GTK_WIDGET (item));
    g_object_set_data (G_OBJECT (item),
		       "Language",
		       LAST_LANGUAGE);
    gtk_tooltips_set_tip (tooltips, GTK_WIDGET (item),
			  _("Log in using the language that you have used "
			    "last time you logged in"),
			  NULL);

    item = gtk_radio_menu_item_new_with_mnemonic (languages, _("_System Default"));
    languages = gtk_radio_menu_item_get_group (GTK_RADIO_MENU_ITEM (item));
    gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
    g_signal_connect (G_OBJECT (item), "activate", 
		      G_CALLBACK (gdm_login_language_handler), 
		      NULL);
    gtk_widget_show (GTK_WIDGET (item));
    g_object_set_data (G_OBJECT (item),
		       "Language",
		       DEFAULT_LANGUAGE);
    gtk_tooltips_set_tip (tooltips, GTK_WIDGET (item),
			  _("Log in using the default system language"),
			  NULL);

    item = gtk_menu_item_new();
    gtk_widget_set_sensitive (item, FALSE);
    gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
    gtk_widget_show (GTK_WIDGET (item));

    item = gtk_menu_item_new_with_label (gdm_lang_group1 ());
    ammenu = gtk_menu_new();
    gtk_menu_item_set_submenu (GTK_MENU_ITEM (item), GTK_WIDGET (ammenu));
    gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
    gtk_widget_show (GTK_WIDGET (item));

    item = gtk_menu_item_new_with_label (gdm_lang_group2 ());
    nzmenu = gtk_menu_new();
    gtk_menu_item_set_submenu (GTK_MENU_ITEM (item), nzmenu);
    gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
    gtk_widget_show(GTK_WIDGET (item));

    other_menu = item = gtk_menu_item_new_with_mnemonic (_("_Other"));
    omenu = gtk_menu_new();
    gtk_menu_item_set_submenu (GTK_MENU_ITEM (item), omenu);
    gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
    gtk_widget_show (GTK_WIDGET (item));

    g1 = gdm_lang_group1 ();
    g2 = gdm_lang_group2 ();

    for (li = langlist; li != NULL; li = li->next) {
	    char *lang = li->data;
	    char *name;
	    char *untranslated;
	    char *group;
	    char *p;
	    GtkWidget *box, *l;

	    li->data = NULL;

	    group = name = gdm_lang_name (lang,
					  FALSE /* never_encoding */,
					  FALSE /* no_group */,
					  FALSE /* untranslated */,
					  FALSE /* markup */);
	    if (name == NULL) {
		    g_free (lang);
		    continue;
	    }

	    untranslated = gdm_lang_untranslated_name (lang,
						       TRUE /* markup */);

	    p = strchr (name, '|');
	    if (p != NULL) {
		    *p = '\0';
		    name = p+1;
	    }

	    box = gtk_hbox_new (FALSE, 5);
	    gtk_widget_show (box);

	    l = gtk_label_new (name);
	    if ( ! gdm_lang_name_translated (lang))
		    gtk_widget_set_direction (l, GTK_TEXT_DIR_LTR);
	    gtk_widget_show (l);
	    gtk_box_pack_start (GTK_BOX (box), l, FALSE, FALSE, 0);

	    if (untranslated != NULL) {
		    l = gtk_label_new (untranslated);
		    /* we really wantd LTR here for the widget */
		    gtk_widget_set_direction (l, GTK_TEXT_DIR_LTR);
		    gtk_label_set_use_markup (GTK_LABEL (l), TRUE);
		    gtk_widget_show (l);
		    gtk_box_pack_end (GTK_BOX (box), l, FALSE, FALSE, 0);
	    }

	    item = gtk_radio_menu_item_new (languages);
	    gtk_container_add (GTK_CONTAINER (item), box);
	    languages = gtk_radio_menu_item_get_group (GTK_RADIO_MENU_ITEM (item));
	    g_object_set_data_full (G_OBJECT (item),
				    "Language",
				    g_strdup (lang),
				    (GDestroyNotify) g_free);

	    if (strcmp (group, g1) == 0) {
		    gtk_menu_shell_append (GTK_MENU_SHELL (ammenu), item);
	    } else if (strcmp (group, g2) == 0) {
		    gtk_menu_shell_append (GTK_MENU_SHELL (nzmenu), item);
	    } else {
		    gtk_menu_shell_append (GTK_MENU_SHELL (omenu), item);
		    has_other_locale = TRUE;
	    }

	    g_signal_connect (G_OBJECT (item), "activate", 
			      G_CALLBACK (gdm_login_language_handler), 
			      NULL);
	    gtk_widget_show (GTK_WIDGET (item));

	    g_free (lang);
	    g_free (group);
	    g_free (untranslated);
    }
    if ( ! has_other_locale) 
	    gtk_widget_destroy (other_menu);

    g_list_free (langlist);

    return menu;
}

static gboolean
theme_allowed (const char *theme)
{
	char **vec;
	int i;

	if (ve_string_empty (GdmGtkThemesToAllow) ||
	    g_ascii_strcasecmp (GdmGtkThemesToAllow, "all") == 0)
		return TRUE;

	vec = g_strsplit (GdmGtkThemesToAllow, ",", 0);
	if (vec == NULL || vec[0] == NULL)
		return TRUE;

	for (i = 0; vec[i] != NULL; i++) {
		if (strcmp (vec[i], theme) == 0)
			return TRUE;
	}

	g_strfreev (vec);

	return FALSE;
}

static GSList *
build_theme_list (void)
{
    DIR *dir;
    struct dirent *de;
    gchar *theme_dir;
    GSList *theme_list = NULL;

    theme_dir = gtk_rc_get_theme_dir ();
    dir = opendir (theme_dir);

    while ((de = readdir (dir))) {
	char *name;
	if (de->d_name[0] == '.')
		continue;
	if ( ! theme_allowed (de->d_name))
		continue;
	name = g_build_filename (theme_dir, de->d_name, GTK_KEY, NULL);
	if (g_file_test (name, G_FILE_TEST_IS_DIR))
		theme_list = g_slist_append (theme_list, g_strdup (de->d_name));
	g_free (name);
    }
    g_free (theme_dir);
    closedir (dir);

    return theme_list;
}

static GtkWidget *
gdm_login_theme_menu_new (void)
{
    GSList *theme_list;
    GtkWidget *item;
    GtkWidget *menu;
    int num = 1;

    if ( ! GdmAllowGtkThemeChange)
	    return NULL;

    menu = gtk_menu_new ();
    
    for (theme_list = build_theme_list ();
	 theme_list != NULL;
	 theme_list = theme_list->next) {
        char *menu_item_name;
        char *theme_name = theme_list->data;
	theme_list->data = NULL;

	if (num < 10)
		menu_item_name = g_strdup_printf ("_%d. %s", num, _(theme_name));
	else if ((num -10) + (int)'a' <= (int)'z')
		menu_item_name = g_strdup_printf ("_%c. %s",
						  (char)(num-10)+'a',
						  _(theme_name));
	else
		menu_item_name = g_strdup (theme_name);
	num ++;

	item = gtk_menu_item_new_with_mnemonic (menu_item_name);
	gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
	gtk_widget_show (GTK_WIDGET (item));
	g_signal_connect (G_OBJECT (item), "activate",
			  G_CALLBACK (gdm_theme_handler), theme_name);
	gtk_tooltips_set_tip (tooltips, GTK_WIDGET (item), _(theme_name), NULL);

	g_free (menu_item_name);
    }
    g_slist_free (theme_list);
    return menu;
}

static gboolean
err_box_clear (gpointer data)
{
	if (err_box != NULL)
		gtk_label_set_text (GTK_LABEL (err_box), "");

	err_box_clear_handler = 0;
	return FALSE;
}

static void
browser_set_user (const char *user)
{
  gboolean old_selecting_user = selecting_user;
  GtkTreeSelection *selection;
  GtkTreeIter iter = {0};
  GtkTreeModel *tm = NULL;

  if (browser == NULL)
    return;

  selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (browser));
  gtk_tree_selection_unselect_all (selection);

  if (ve_string_empty (user))
    return;

  selecting_user = FALSE;

  tm = gtk_tree_view_get_model (GTK_TREE_VIEW (browser));

  if (gtk_tree_model_get_iter_first (tm, &iter))
    {
      do
        {
          char *login;
	  gtk_tree_model_get (tm, &iter, GREETER_ULIST_LOGIN_COLUMN,
			      &login, -1);
	  if (login != NULL && strcmp (user, login) == 0)
	    {
	      GtkTreePath *path = gtk_tree_model_get_path (tm, &iter);
	      gtk_tree_selection_select_iter (selection, &iter);
	      gtk_tree_view_scroll_to_cell (GTK_TREE_VIEW (browser),
					    path, NULL,
					    FALSE, 0.0, 0.0);
	      gtk_tree_path_free (path);
	      break;
	    }
	  
        }
      while (gtk_tree_model_iter_next (tm, &iter));
    }
  selecting_user = old_selecting_user;
}

static Display *
get_parent_display (void)
{
  static gboolean tested = FALSE;
  static Display *dsp = NULL;

  if (tested)
    return dsp;

  tested = TRUE;

  if (g_getenv ("GDM_PARENT_DISPLAY") != NULL)
    {
      char *old_xauth = g_strdup (g_getenv ("XAUTHORITY"));
      if (g_getenv ("GDM_PARENT_XAUTHORITY") != NULL)
        {
	  ve_setenv ("XAUTHORITY",
		     g_getenv ("GDM_PARENT_XAUTHORITY"), TRUE);
	}
      dsp = XOpenDisplay (g_getenv ("GDM_PARENT_DISPLAY"));
      if (old_xauth != NULL)
        ve_setenv ("XAUTHORITY", old_xauth, TRUE);
      else
        ve_unsetenv ("XAUTHORITY");
      g_free (old_xauth);
    }

  return dsp;
}

static gboolean
greeter_is_capslock_on (void)
{
  unsigned int states;
  Display *dsp;

  /* HACK! incredible hack, if GDM_PARENT_DISPLAY is set we get
   * indicator state from the parent display, since we must be inside an
   * Xnest */
  dsp = get_parent_display ();
  if (dsp == NULL)
    dsp = GDK_DISPLAY ();

  if (XkbGetIndicatorState (dsp, XkbUseCoreKbd, &states) != Success)
      return FALSE;

  return (states & ShiftMask) != 0;
}

static gboolean
gdm_login_ctrl_handler (GIOChannel *source, GIOCondition cond, gint fd)
{
    gchar buf[PIPE_SIZE];
    gsize len;
    char *tmp;
    gint i, x, y;
    GtkWidget *dlg;
    static gboolean replace_msg = TRUE;
    static gboolean messages_to_give = FALSE;

    /* If this is not incoming i/o then return */
    if (cond != G_IO_IN) 
	return (TRUE);

    /* Read random garbage from i/o channel until STX is found */
    do {
	g_io_channel_read_chars (source, buf, 1, &len, NULL);

	if (len != 1)
	    return (TRUE);
    } while (buf[0] && buf[0] != STX);


    /* Read opcode */
    g_io_channel_read_chars (source, buf, 1, &len, NULL);

    /* If opcode couldn't be read */
    if (len != 1)
	return (TRUE);

    /* Parse opcode */
    switch (buf[0]) {
    case GDM_SETLOGIN:
	/* somebody is trying to fool us this is the user that
	 * wants to log in, and well, we are the gullible kind */
        g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL);
	buf[len-1] = '\0';
	g_free (curuser);
	curuser = g_strdup (buf);
	if (GdmBrowser) {
		browser_set_user (curuser);
		if (ve_string_empty (curuser))
			gtk_widget_set_sensitive (GTK_WIDGET (browser), TRUE);
		else
			gtk_widget_set_sensitive (GTK_WIDGET (browser), FALSE);
	}
	printf ("%c\n", STX);
	fflush (stdout);
	break;

    case GDM_PROMPT:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL);
	buf[len-1] = '\0';

	tmp = ve_locale_to_utf8 (buf);
	if (strcmp (tmp, _("Username:")) == 0) {
		gdm_common_login_sound ();
		gtk_label_set_text_with_mnemonic (GTK_LABEL (label), _("_Username:"));
                if (ve_string_empty(gtk_label_get_text (GTK_LABEL (msg)))) {
                        gtk_label_set_text (GTK_LABEL (msg), _("Please enter your username"));
                        using_fallback_message = TRUE;
                }
	} else {
		gtk_label_set_text (GTK_LABEL (label), tmp);
                if (using_fallback_message) {
                        gtk_label_set_text (GTK_LABEL (msg), "");
                        using_fallback_message = FALSE;
                }
	}
	g_free (tmp);

	gtk_widget_show (GTK_WIDGET (label));
	gtk_entry_set_text (GTK_ENTRY (entry), "");
	gtk_entry_set_max_length (GTK_ENTRY (entry), 128);
	gtk_entry_set_visibility (GTK_ENTRY (entry), TRUE);
	gtk_widget_set_sensitive (entry, TRUE);
	gtk_widget_set_sensitive (ok_button, TRUE);
	gtk_widget_grab_focus (entry);	
	gtk_window_set_focus (GTK_WINDOW (login), entry);	
	gtk_widget_show (entry);

	/* replace rather then append next message string */
	replace_msg = TRUE;

	/* the user has seen messages */
	messages_to_give = FALSE;

	login_window_resize (FALSE /* force */);
	break;

    case GDM_NOECHO:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL);
	buf[len-1] = '\0';

	tmp = ve_locale_to_utf8 (buf);
	if (strcmp (tmp, _("Password:")) == 0) {
		gtk_label_set_text_with_mnemonic (GTK_LABEL (label), _("_Password:"));
	} else {
		gtk_label_set_text (GTK_LABEL (label), tmp);
	}
	g_free (tmp);

	gtk_widget_show (GTK_WIDGET (label));
	gtk_entry_set_text (GTK_ENTRY (entry), "");
	gtk_entry_set_max_length (GTK_ENTRY (entry), 128);
	gtk_entry_set_visibility (GTK_ENTRY (entry), FALSE);
	gtk_widget_set_sensitive (entry, TRUE);
	gtk_widget_set_sensitive (ok_button, TRUE);
	gtk_widget_grab_focus (entry);	
	gtk_window_set_focus (GTK_WINDOW (login), entry);	
	gtk_widget_show (entry);

	/* replace rather then append next message string */
	replace_msg = TRUE;

	/* the user has seen messages */
	messages_to_give = FALSE;

	login_window_resize (FALSE /* force */);
	break;

    case GDM_MSG:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL);
	buf[len-1] = '\0';

	/* the user has not yet seen messages */
	messages_to_give = TRUE;

	/* HAAAAAAACK.  Sometimes pam sends many many messages, SO
	 * we try to collect them until the next prompt or reset or
	 * whatnot */
	if ( ! replace_msg &&
	   /* empty message is for clearing */
	   ! ve_string_empty (buf)) {
		const char *oldtext;
		oldtext = gtk_label_get_text (GTK_LABEL (msg));
		if ( ! ve_string_empty (oldtext)) {
			char *newtext;
			tmp = ve_locale_to_utf8 (buf);
			newtext = g_strdup_printf ("%s\n%s", oldtext, tmp);
			g_free (tmp);
			gtk_label_set_text (GTK_LABEL (msg), newtext);
			g_free (newtext);
		} else {
			tmp = ve_locale_to_utf8 (buf);
			gtk_label_set_text (GTK_LABEL (msg), tmp);
			g_free (tmp);
		}
	} else {
		tmp = ve_locale_to_utf8 (buf);
		gtk_label_set_text (GTK_LABEL (msg), tmp);
		g_free (tmp);
	}
	replace_msg = FALSE;
        using_fallback_message = FALSE;

	gtk_widget_show (GTK_WIDGET (msg));
	printf ("%c\n", STX);
	fflush (stdout);

	login_window_resize (FALSE /* force */);

	break;

    case GDM_ERRBOX:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL);
	buf[len-1] = '\0';
	tmp = ve_locale_to_utf8 (buf);
	gtk_label_set_text (GTK_LABEL (err_box), tmp);
	g_free (tmp);
	if (err_box_clear_handler > 0)
		g_source_remove (err_box_clear_handler);
	if (ve_string_empty (buf))
		err_box_clear_handler = 0;
	else
		err_box_clear_handler = g_timeout_add (30000,
						       err_box_clear,
						       NULL);
	printf ("%c\n", STX);
	fflush (stdout);

	login_window_resize (FALSE /* force */);
	break;

    case GDM_ERRDLG:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL);
	buf[len-1] = '\0';

	/* we should be now fine for focusing new windows */
	gdm_wm_focus_new_windows (TRUE);

	tmp = ve_locale_to_utf8 (buf);
	dlg = ve_hig_dialog_new (NULL /* parent */,
				 GTK_DIALOG_MODAL /* flags */,
				 GTK_MESSAGE_ERROR,
				 GTK_BUTTONS_OK,
				 FALSE /* markup */,
				 tmp,
				 /* avoid warning */ "%s", "");
	g_free (tmp);

	gdm_wm_center_window (GTK_WINDOW (dlg));

	gdm_wm_no_login_focus_push ();
	gtk_dialog_run (GTK_DIALOG (dlg));
	gtk_widget_destroy (dlg);
	gdm_wm_no_login_focus_pop ();

	printf ("%c\n", STX);
	fflush (stdout);
	break;

    case GDM_SESS:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL);
	buf[len-1] = '\0';
	tmp = ve_locale_to_utf8 (buf);
	gdm_login_session_lookup (tmp);
	g_free (tmp);
	tmp = ve_locale_from_utf8 (session);
	printf ("%c%s\n", STX, tmp);
	fflush (stdout);
	g_free (tmp);
	break;

    case GDM_LANG:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL);
	buf[len-1] = '\0';
	gdm_login_language_lookup (buf);
	printf ("%c%s\n", STX, language);
	fflush (stdout);
	break;

    case GDM_SSESS:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL); /* Empty */

	if (savesess)
	    printf ("%cY\n", STX);
	else
	    printf ("%c\n", STX);
	fflush (stdout);
	
	break;

    case GDM_SLANG:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL); /* Empty */

	if (savelang)
	    printf ("%cY\n", STX);
	else
	    printf ("%c\n", STX);
	fflush (stdout);

	break;

    case GDM_RESET:
	if (GdmQuiver &&
	    login->window != NULL &&
	    icon_win == NULL &&
	    GTK_WIDGET_VISIBLE (login)) {
		Window lw = GDK_WINDOW_XWINDOW (login->window);

		gdm_wm_get_window_pos (lw, &x, &y);

		for (i = 32 ; i > 0 ; i = i/4) {
			gdm_wm_move_window_now (lw, i+x, y);
			usleep (200);
			gdm_wm_move_window_now (lw, x, y);
			usleep (200);
			gdm_wm_move_window_now (lw, -i+x, y);
			usleep (200);
			gdm_wm_move_window_now (lw, x, y);
			usleep (200);
		}
	}
	/* fall thru to reset */

    case GDM_RESETOK:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL);
	buf[len-1] = '\0';

	if (curuser != NULL) {
	    g_free (curuser);
	    curuser = NULL;
	}

	gtk_widget_set_sensitive (entry, TRUE);
	gtk_widget_set_sensitive (ok_button, TRUE);

	if (GdmBrowser)
	    gtk_widget_set_sensitive (GTK_WIDGET (browser), TRUE);

	tmp = ve_locale_to_utf8 (buf);
	gtk_label_set_text (GTK_LABEL (msg), tmp);
	g_free (tmp);
	gtk_widget_show (GTK_WIDGET (msg));

	printf ("%c\n", STX);
	fflush (stdout);

	login_window_resize (FALSE /* force */);
	break;

    case GDM_QUIT:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL); /* Empty */

	if (timed_handler_id != 0) {
		g_source_remove (timed_handler_id);
		timed_handler_id = 0;
	}

	if (require_quarter) {
		/* we should be now fine for focusing new windows */
		gdm_wm_focus_new_windows (TRUE);

		dlg = ve_hig_dialog_new (NULL /* parent */,
					 GTK_DIALOG_MODAL /* flags */,
					 GTK_MESSAGE_INFO,
					 GTK_BUTTONS_OK,
					 FALSE /* markup */,
					 /* translators:  This is a nice and evil eggie text, translate
					  * to your favourite currency */
					 _("Please insert 25 cents "
					   "to log in."),
					 /* avoid warning */ "%s", "");
		gdm_wm_center_window (GTK_WINDOW (dlg));

		gdm_wm_no_login_focus_push ();
		gtk_dialog_run (GTK_DIALOG (dlg));
		gtk_widget_destroy (dlg);
		gdm_wm_no_login_focus_pop ();
	}

	/* Hide the login window now */
	gtk_widget_hide (login);

	if (messages_to_give) {
		const char *oldtext;
		oldtext = gtk_label_get_text (GTK_LABEL (msg));

		if ( ! ve_string_empty (oldtext)) {
			/* we should be now fine for focusing new windows */
			gdm_wm_focus_new_windows (TRUE);

			dlg = ve_hig_dialog_new (NULL /* parent */,
						 GTK_DIALOG_MODAL /* flags */,
						 GTK_MESSAGE_INFO,
						 GTK_BUTTONS_OK,
						 FALSE /* markup */,
						 oldtext,
						 /* avoid warning */ "%s", "");
			gtk_window_set_modal (GTK_WINDOW (dlg), TRUE);
			gdm_wm_center_window (GTK_WINDOW (dlg));

			gdm_wm_no_login_focus_push ();
			gtk_dialog_run (GTK_DIALOG (dlg));
			gtk_widget_destroy (dlg);
			gdm_wm_no_login_focus_pop ();
		}
		messages_to_give = FALSE;
	}

	gdm_kill_thingies ();

	gdk_flush ();

	printf ("%c\n", STX);
	fflush (stdout);

	/* screw gtk_main_quit, we want to make sure we definately die */
	_exit (EXIT_SUCCESS);
	break;

    case GDM_STARTTIMER:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL); /* Empty */

	/*
	 * Timed Login: Start Timer Loop
	 */

	if (timed_handler_id == 0 &&
	    ! ve_string_empty (GdmTimedLogin) &&
	    GdmTimedLoginDelay > 0) {
		curdelay = GdmTimedLoginDelay;
		timed_handler_id = g_timeout_add (1000,
						  gdm_timer, NULL);
	}
	printf ("%c\n", STX);
	fflush (stdout);
	break;

    case GDM_STOPTIMER:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL); /* Empty */

	/*
	 * Timed Login: Stop Timer Loop
	 */

	if (timed_handler_id != 0) {
		g_source_remove (timed_handler_id);
		timed_handler_id = 0;
	}
	printf ("%c\n", STX);
	fflush (stdout);
	break;

    case GDM_DISABLE:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL); /* Empty */
	if (clock_label != NULL)
		GTK_WIDGET_SET_FLAGS (clock_label->parent, GTK_SENSITIVE);
	gtk_widget_set_sensitive (login, FALSE);
	printf ("%c\n", STX);
	fflush (stdout);
	break;

    case GDM_ENABLE:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL); /* Empty */
	gtk_widget_set_sensitive (login, TRUE);
	if (clock_label != NULL)
		GTK_WIDGET_UNSET_FLAGS (clock_label->parent, GTK_SENSITIVE);
	printf ("%c\n", STX);
	fflush (stdout);
	break;

    /* These are handled separately so ignore them here and send
     * back a NULL response so that the daemon quits sending them */
    case GDM_NEEDPIC:
    case GDM_READPIC:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL); /* Empty */
	printf ("%c\n", STX);
	fflush (stdout);
	break;

    case GDM_NOFOCUS:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL); /* Empty */

	gdm_wm_no_login_focus_push ();
	
	printf ("%c\n", STX);
	fflush (stdout);
	break;

    case GDM_FOCUS:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL); /* Empty */

	gdm_wm_no_login_focus_pop ();
	
	printf ("%c\n", STX);
	fflush (stdout);
	break;

    case GDM_SAVEDIE:
	g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL); /* Empty */

	/* Set busy cursor */
	gdm_common_setup_cursor (GDK_WATCH);

	gdm_wm_save_wm_order ();

	gdm_kill_thingies ();
	gdk_flush ();

	_exit (EXIT_SUCCESS);

    case GDM_QUERY_CAPSLOCK:
        g_io_channel_read_chars (source, buf, PIPE_SIZE-1, &len, NULL); /* Empty */

	if (greeter_is_capslock_on ())
	    printf ("%cY\n", STX);
	else
	    printf ("%c\n", STX);
	fflush (stdout);

	break;
	
    default:
	gdm_common_abort ("Unexpected greeter command received: '%c'", buf[0]);
	break;
    }

    return (TRUE);
}


static void
gdm_login_browser_populate (void)
{
    GList *li;

    for (li = users; li != NULL; li = li->next) {
	    GdmLoginUser *usr = li->data;
	    GtkTreeIter iter = {0};
	    char *label;
	    char *login, *gecos;

	    login = g_markup_escape_text (usr->login, -1);
	    gecos = g_markup_escape_text (usr->gecos, -1);

	    label = g_strdup_printf ("<b>%s</b>\n%s",
				     login,
				     gecos);

	    g_free (login);
	    g_free (gecos);
	    gtk_list_store_append (GTK_LIST_STORE (browser_model), &iter);
	    gtk_list_store_set (GTK_LIST_STORE (browser_model), &iter,
				GREETER_ULIST_ICON_COLUMN, usr->picture,
				GREETER_ULIST_LOGIN_COLUMN, usr->login,
				GREETER_ULIST_LABEL_COLUMN, label,
				-1);
	    g_free (label);
    }
}

static gboolean
resize_in_time (gpointer data)
{
	login_window_resize (FALSE /* force */);
	return FALSE;
}

static int
get_double_click_time (void)
{
	/* FIXME: what about multihead? */
	GtkSettings *settings = gtk_settings_get_default ();
	int t;

	g_object_get (G_OBJECT (settings),
		      "gtk-double-click-time",
		      &t,
		      NULL);

	/* sanity */
	if (t < 100)
		t = 100;
	if (t > 1500)
		t = 1500;

	return t;
}

static void
user_selected (GtkTreeSelection *selection, gpointer data)
{
  GtkTreeModel *tm = NULL;
  GtkTreeIter iter = {0};

  if ( ! ve_string_empty (curuser))
	  /* eek, this shouldn't get here, but just in case */
	  return;

  g_free (selected_browser_user);
  selected_browser_user = NULL;

  if (gtk_tree_selection_get_selected (selection, &tm, &iter)) {
	  char *login;
	  gtk_tree_model_get (tm, &iter, GREETER_ULIST_LOGIN_COLUMN,
			      &login, -1);
	  if (login != NULL) {
		  const char *str;
		  str = gtk_label_get_text (GTK_LABEL (label));
		  if (selecting_user &&
		      str != NULL &&
		      (strcmp (str, _("Username:")) == 0 ||
		       strcmp (str, _("_Username:")) == 0)) {
			  /* This is pretty evil, but we really don't
			     know when it is ok to set the entry */
			  gtk_entry_set_text (GTK_ENTRY (entry), login);
		  }
		  selected_browser_user = g_strdup (login);
		  if (selecting_user) {
			  gtk_label_set_text (GTK_LABEL (msg),
					      _("Doubleclick on the user "
						"to log in"));
			  g_timeout_add (get_double_click_time (),
					 resize_in_time, NULL); 
		  }
	  }
  }
}

static void
row_activated (GtkTreeView *tree_view,
	       GtkTreePath *path,
	       GtkTreeViewColumn *column)
{
	if (selected_browser_user != NULL) {
		gtk_widget_set_sensitive (entry, FALSE);
		gtk_widget_set_sensitive (ok_button, FALSE);
		gtk_widget_set_sensitive (GTK_WIDGET (browser),
					  FALSE);
		printf ("%c%c%c%s\n", STX, BEL, GDM_INTERRUPT_SELECT_USER,
			selected_browser_user);
		fflush (stdout);
	}
}

static gboolean
gdm_login_handle_pressed (GtkWidget *widget, GdkEventButton *event)
{
    gint xp, yp;
    GdkModifierType mask;
    CursorOffset *p;
    GdkCursor *fleur_cursor;

    if (login == NULL ||
	login->window == NULL ||
	event->type != GDK_BUTTON_PRESS ||
	GdmLockPosition)
	    return FALSE;

    gdk_window_raise (login->window);

    p = g_new0 (CursorOffset, 1);
    g_object_set_data_full (G_OBJECT (widget), "offset", p,
			    (GDestroyNotify)g_free);
    
    gdk_window_get_pointer (login->window, &xp, &yp, &mask);
    p->x = xp;
    p->y = yp;

    gtk_grab_add (widget);
    fleur_cursor = gdk_cursor_new (GDK_FLEUR);
    gdk_pointer_grab (widget->window, TRUE,
		      GDK_BUTTON_RELEASE_MASK |
		      GDK_BUTTON_MOTION_MASK |
		      GDK_POINTER_MOTION_HINT_MASK,
		      NULL,
		      fleur_cursor,
		      GDK_CURRENT_TIME);
    gdk_cursor_unref (fleur_cursor);
    gdk_flush ();
    
    return TRUE;
}

static gboolean
gdm_login_handle_released (GtkWidget *widget, GdkEventButton *event)
{
	gtk_grab_remove (widget);
	gdk_pointer_ungrab (GDK_CURRENT_TIME);

	g_object_set_data (G_OBJECT (widget), "offset", NULL);

	return TRUE;
}


static gboolean
gdm_login_handle_motion (GtkWidget *widget, GdkEventMotion *event)
{
    int xp, yp;
    CursorOffset *p;
    GdkModifierType mask;

    p = g_object_get_data (G_OBJECT (widget), "offset");

    if (p == NULL)
	    return FALSE;

    gdk_window_get_pointer (gdk_get_default_root_window (), &xp, &yp, &mask);

    set_screen_to_pos (xp, yp);

    GdmSetPosition = TRUE;
    GdmPositionX = xp - p->x;
    GdmPositionY = yp - p->y;

    if (GdmPositionX < 0)
	    GdmPositionX = 0;
    if (GdmPositionY < 0)
	    GdmPositionY = 0;

    set_screen_pos (GTK_WIDGET (login), GdmPositionX, GdmPositionY);

    return TRUE;
}

static GtkWidget *
create_handle (void)
{
	GtkWidget *hbox, *w;

	title_box = gtk_event_box_new ();
	g_signal_connect (G_OBJECT (title_box), "button_press_event",
			  G_CALLBACK (gdm_login_handle_pressed),
			  NULL);
	g_signal_connect (G_OBJECT (title_box), "button_release_event",
			  G_CALLBACK (gdm_login_handle_released),
			  NULL);
	g_signal_connect (G_OBJECT (title_box), "motion_notify_event",
			  G_CALLBACK (gdm_login_handle_motion),
			  NULL);

	hbox = gtk_hbox_new (FALSE, 0);
	gtk_container_add (GTK_CONTAINER (title_box), hbox);

	w = gtk_label_new (_("GNOME Desktop Manager"));
	gtk_misc_set_padding (GTK_MISC (w),
			      GNOME_PAD_SMALL, GNOME_PAD_SMALL);
	gtk_box_pack_start (GTK_BOX (hbox), w,
			    TRUE, TRUE, GNOME_PAD_SMALL);
	
	gtk_widget_show_all (title_box);

	return title_box;
}

static gboolean
update_clock (gpointer data)
{
	struct tm *the_tm;
	char *str;
	time_t the_time;
	gint time_til_next_min;

	if (clock_label == NULL)
		return FALSE;

	time (&the_time);
	the_tm = localtime (&the_time);

	if (GdmUse24Clock) {
		str = ve_strftime (the_tm, _("%a %b %d, %H:%M"));
	} else {
		str = ve_strftime (the_tm, _("%a %b %d, %l:%M %p"));
  	}

	gtk_label_set_text (GTK_LABEL (clock_label), str);
	g_free (str);

	/* account for leap seconds */
	time_til_next_min = 60 - the_tm->tm_sec;
	time_til_next_min = (time_til_next_min>=0?time_til_next_min:0);

	g_timeout_add (time_til_next_min*1000, update_clock, NULL);
	
	return FALSE;
}

/* doesn't check for executability, just for existance */
static gboolean
bin_exists (const char *command)
{
	char *bin;

	if (ve_string_empty (command))
		return FALSE;

	/* Note, check only for existance, not for executability */
	bin = ve_first_word (command);
	if (bin != NULL &&
	    access (bin, F_OK) == 0) {
		g_free (bin);
		return TRUE;
	} else {
		g_free (bin);
		return FALSE;
	}
}

static gboolean
window_browser_event (GtkWidget *window, GdkEvent *event, gpointer data)
{
	switch (event->type) {
		/* FIXME: Fix fingering cuz it's cool */
#ifdef FIXME
	case GDK_KEY_PRESS:
		if ((event->key.state & GDK_CONTROL_MASK) &&
		    (event->key.keyval == GDK_f ||
		     event->key.keyval == GDK_F) &&
		    selected_browser_user != NULL) {
			GtkWidget *d, *less;
			char *command;
			d = gtk_dialog_new_with_buttons (_("Finger"),
							 NULL /* parent */,
							 0 /* flags */,
							 GTK_STOCK_OK,
							 GTK_RESPONSE_OK,
							 NULL);
			gtk_dialog_set_has_separator (GTK_DIALOG (d), FALSE);
			less = gnome_less_new ();
			gtk_widget_show (less);
			gtk_box_pack_start (GTK_BOX (GTK_DIALOG (d)->vbox),
					    less,
					    TRUE,
					    TRUE,
					    0);

			/* hack to make this be the size of a terminal */
			gnome_less_set_fixed_font (GNOME_LESS (less), TRUE);
			{
				int i;
				char buf[82];
				GtkWidget *text = GTK_WIDGET (GNOME_LESS (less)->text);
				GdkFont *font = GNOME_LESS (less)->font;
				for (i = 0; i < 81; i++)
					buf[i] = 'X';
				buf[i] = '\0';
				gtk_widget_set_size_request
					(text,
					 gdk_string_width (font, buf) + 30,
					 gdk_string_height (font, buf)*24+30);
			}

			command = g_strconcat ("finger ",
					       selected_browser_user,
					       NULL);
			gnome_less_show_command (GNOME_LESS (less), command);

			gtk_widget_grab_focus (GTK_WIDGET (less));

			gtk_window_set_modal (GTK_WINDOW (d), TRUE);
			gdm_wm_center_window (GTK_WINDOW (d));

			gdm_wm_no_login_focus_push ();
			gtk_dialog_run (GTK_DIALOG (d));
			gtk_widget_destroy (d);
			gdm_wm_no_login_focus_pop ();
		}
		break;
#endif
	default:
		break;
	}

	return FALSE;
}

static gboolean
key_press_event (GtkWidget *entry, GdkEventKey *event, gpointer data)
{
	if ((event->keyval == GDK_Tab ||
	     event->keyval == GDK_KP_Tab) &&
	    (event->state & (GDK_CONTROL_MASK|GDK_MOD1_MASK|GDK_SHIFT_MASK)) == 0) {
		g_signal_emit_by_name (entry,
				       "insert_at_cursor",
				       "\t");
		return TRUE;
	}

	return FALSE;
}


static void
gdm_login_gui_init (void)
{
    GtkWidget *frame1, *frame2, *ebox;
    GtkWidget *mbox, *menu, *menubar, *item;
    GtkWidget *stack, *hline1, *hline2, *handle;
    GtkWidget *bbox = NULL;
    GtkWidget /**help_button,*/ *button_box;
    gchar *greeting;
    gint rows;
    GdkPixbuf *pb;
    GtkWidget *frame;
    int lw, lh;
    gboolean have_logo = FALSE;
    GtkWidget *thememenu;
    const gchar *theme_name;

    theme_name = g_getenv ("GDM_GTK_THEME");
    if (ve_string_empty (theme_name))
	    theme_name = GdmGtkTheme;

    if( ! ve_string_empty (GdmGtkRC))
	    gtk_rc_parse (GdmGtkRC);

    if ( ! ve_string_empty (theme_name)) {
	    gdm_set_theme (theme_name);
    }

    login = gtk_window_new (GTK_WINDOW_TOPLEVEL);
    g_object_ref (login);
    g_object_set_data_full (G_OBJECT (login), "login", login,
			    (GDestroyNotify) g_object_unref);

    gtk_widget_set_events (login, GDK_ALL_EVENTS_MASK);

    gtk_window_set_title (GTK_WINDOW (login), _("GDM Login"));
    /* connect for fingering */
    if (GdmBrowser)
	    g_signal_connect (G_OBJECT (login), "event",
			      G_CALLBACK (window_browser_event),
			      NULL);

    frame1 = gtk_frame_new (NULL);
    gtk_frame_set_shadow_type (GTK_FRAME (frame1), GTK_SHADOW_OUT);
    gtk_container_set_border_width (GTK_CONTAINER (frame1), 0);
    gtk_container_add (GTK_CONTAINER (login), frame1);
    g_object_set_data_full (G_OBJECT (login), "frame1", frame1,
			    (GDestroyNotify) gtk_widget_unref);
    gtk_widget_ref (GTK_WIDGET (frame1));
    gtk_widget_show (GTK_WIDGET (frame1));

    frame2 = gtk_frame_new(NULL);
    gtk_frame_set_shadow_type (GTK_FRAME (frame2), GTK_SHADOW_IN);
    gtk_container_set_border_width (GTK_CONTAINER (frame2), 2);
    gtk_container_add (GTK_CONTAINER (frame1), frame2);
    g_object_set_data_full (G_OBJECT (login), "frame2", frame2,
			    (GDestroyNotify) gtk_widget_unref);
    gtk_widget_ref (GTK_WIDGET (frame2));
    gtk_widget_show (GTK_WIDGET (frame2));

    mbox = gtk_vbox_new (FALSE, 0);
    gtk_widget_ref (mbox);
    g_object_set_data_full (G_OBJECT (login), "mbox", mbox,
			    (GDestroyNotify) gtk_widget_unref);
    gtk_widget_show (mbox);
    gtk_container_add (GTK_CONTAINER (frame2), mbox);

    if (GdmTitleBar) {
	    handle = create_handle ();
	    gtk_box_pack_start (GTK_BOX (mbox), handle, FALSE, FALSE, 0);
    }

    menubar = gtk_menu_bar_new();
    gtk_widget_ref (GTK_WIDGET (menubar));
    gtk_box_pack_start (GTK_BOX (mbox), menubar, FALSE, FALSE, 0);

    menu = gtk_menu_new();
    gdm_login_session_init (menu);
    sessmenu = gtk_menu_item_new_with_mnemonic (_("_Session"));
    gtk_menu_shell_append (GTK_MENU_SHELL (menubar), sessmenu);
    gtk_menu_item_set_submenu (GTK_MENU_ITEM (sessmenu), menu);
    gtk_widget_show (GTK_WIDGET (sessmenu));

    menu = gdm_login_language_menu_new ();
    if (menu != NULL) {
	langmenu = gtk_menu_item_new_with_mnemonic (_("_Language"));
	gtk_menu_shell_append (GTK_MENU_SHELL (menubar), langmenu);
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (langmenu), menu);
	gtk_widget_show (GTK_WIDGET (langmenu));
    }

    if (GdmSystemMenuReal) {
        gboolean got_anything = FALSE;

	menu = gtk_menu_new();

	if (GdmChooserButtonReal) {
		item = gtk_menu_item_new_with_mnemonic (_("_XDMCP Chooser..."));
		gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
		g_signal_connect (G_OBJECT (item), "activate",
				  G_CALLBACK (gdm_login_use_chooser_handler),
				  NULL);
		gtk_widget_show (item);
		gtk_tooltips_set_tip (tooltips, GTK_WIDGET (item),
				      _("Run an XDMCP chooser which will allow "
					"you to log into available remote "
					"machines, if there are any."),
				      NULL);
		got_anything = TRUE;
	}

	if (GdmConfigAvailableReal &&
	    bin_exists (GdmConfigurator)) {
		item = gtk_menu_item_new_with_mnemonic (_("_Configure Login Manager..."));
		gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
		g_signal_connect (G_OBJECT (item), "activate",
				  G_CALLBACK (gdm_run_gdmconfig),
				  NULL);
		gtk_widget_show (item);
		gtk_tooltips_set_tip (tooltips, GTK_WIDGET (item),
				      _("Configure GDM (this login manager). "
					"This will require the root password."),
				      NULL);
		got_anything = TRUE;
	}

	if (gdm_working_command_exists (GdmReboot)) {
		item = gtk_menu_item_new_with_mnemonic (_("_Reboot"));
		gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
		g_signal_connect (G_OBJECT (item), "activate",
				  G_CALLBACK (gdm_login_reboot_handler), 
				  NULL);
		gtk_widget_show (GTK_WIDGET (item));
		gtk_tooltips_set_tip (tooltips, GTK_WIDGET (item),
				      _("Reboot your computer"),
				      NULL);
		got_anything = TRUE;
	}
	
	if (gdm_working_command_exists (GdmHalt)) {
		item = gtk_menu_item_new_with_mnemonic (_("Shut _Down"));
		gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
		g_signal_connect (G_OBJECT (item), "activate",
				  G_CALLBACK (gdm_login_halt_handler), 
				  NULL);
		gtk_widget_show (GTK_WIDGET (item));
		gtk_tooltips_set_tip (tooltips, GTK_WIDGET (item),
				      _("Shut down the system so that "
					"you may safely turn off the computer."),
				      NULL);
		got_anything = TRUE;
	}

	if (gdm_working_command_exists (GdmSuspend)) {
		item = gtk_menu_item_new_with_mnemonic (_("_Suspend"));
		gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
		g_signal_connect (G_OBJECT (item), "activate",
				  G_CALLBACK (gdm_login_suspend_handler), 
				  NULL);
		gtk_widget_show (GTK_WIDGET (item));
		gtk_tooltips_set_tip (tooltips, GTK_WIDGET (item),
				      _("Suspend your computer"),
				      NULL);
		got_anything = TRUE;
	}
	
	if (got_anything) {
		item = gtk_menu_item_new_with_mnemonic (_("_Actions"));
		gtk_menu_shell_append (GTK_MENU_SHELL (menubar), item);
		gtk_menu_item_set_submenu (GTK_MENU_ITEM (item), menu);
		gtk_widget_show (GTK_WIDGET (item));
	}
    }

    menu = gdm_login_theme_menu_new ();
    if (menu != NULL) {
	thememenu = gtk_menu_item_new_with_mnemonic (_("_Theme"));
	gtk_menu_shell_append (GTK_MENU_SHELL (menubar), thememenu);
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (thememenu), menu);
	gtk_widget_show (GTK_WIDGET (thememenu));
    }

    /* Add a quit/disconnect item when in xdmcp mode or flexi mode */
    /* Do note that the order is important, we always want "Quit" for
     * flexi, even if not local (non-local xnest).  and Disconnect
     * only for xdmcp */
    if ( ! ve_string_empty (g_getenv ("GDM_FLEXI_SERVER"))) {
	    item = gtk_menu_item_new_with_mnemonic (_("_Quit"));
    } else if (ve_string_empty (g_getenv ("GDM_IS_LOCAL"))) {
	    item = gtk_menu_item_new_with_mnemonic (_("D_isconnect"));
    } else {
	    item = NULL;
    }
    if (item != NULL) {
	    gtk_menu_shell_append (GTK_MENU_SHELL (menubar), item);
	    gtk_widget_show (GTK_WIDGET (item));
	    g_signal_connect (G_OBJECT (item), "activate",
			      G_CALLBACK (gtk_main_quit), NULL);
    }

    /* The clock */
    clock_label = gtk_label_new ("");
    gtk_widget_show (clock_label);
    item = gtk_menu_item_new ();
    gtk_container_add (GTK_CONTAINER (item), clock_label);
    gtk_widget_show (item);
    gtk_menu_shell_append (GTK_MENU_SHELL (menubar), item);
    gtk_menu_item_set_right_justified (GTK_MENU_ITEM (item), TRUE);
    GTK_WIDGET_UNSET_FLAGS (item, GTK_SENSITIVE);

    g_signal_connect (G_OBJECT (clock_label), "destroy",
		      G_CALLBACK (gtk_widget_destroyed),
		      &clock_label);

    update_clock (NULL); 

    if (GdmBrowser)
	rows = 2;
    else
	rows = 1;

    table = gtk_table_new (rows, 2, FALSE);
    gtk_widget_ref (table);
    g_object_set_data_full (G_OBJECT (login), "table", table,
			    (GDestroyNotify) gtk_widget_unref);
    gtk_widget_show (table);
    gtk_box_pack_start (GTK_BOX (mbox), table, TRUE, TRUE, 0);
    gtk_container_set_border_width (GTK_CONTAINER (table), 10);
    gtk_table_set_row_spacings (GTK_TABLE (table), 10);
    gtk_table_set_col_spacings (GTK_TABLE (table), 10);

    if (GdmBrowser) {
	    int height;
	    GtkTreeSelection *selection;
	    GtkTreeViewColumn *column;

	    browser = gtk_tree_view_new ();
	    gtk_tree_view_set_rules_hint (GTK_TREE_VIEW (browser), TRUE);
	    gtk_tree_view_set_headers_visible (GTK_TREE_VIEW (browser),
					       FALSE);
	    selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (browser));
	    gtk_tree_selection_set_mode (selection, GTK_SELECTION_SINGLE);

	    g_signal_connect (selection, "changed",
			      G_CALLBACK (user_selected),
			      NULL);
	    g_signal_connect (browser, "row_activated",
			      G_CALLBACK (row_activated),
			      NULL);

	    browser_model = (GtkTreeModel *)gtk_list_store_new (3,
								GDK_TYPE_PIXBUF,
								G_TYPE_STRING,
								G_TYPE_STRING);
	    gtk_tree_view_set_model (GTK_TREE_VIEW (browser), browser_model);
	    column = gtk_tree_view_column_new_with_attributes
		    (_("Icon"),
		     gtk_cell_renderer_pixbuf_new (),
		     "pixbuf", GREETER_ULIST_ICON_COLUMN,
		     NULL);
	    gtk_tree_view_append_column (GTK_TREE_VIEW (browser), column);
      
	    column = gtk_tree_view_column_new_with_attributes
		    (_("Username"),
		     gtk_cell_renderer_text_new (),
		     "markup", GREETER_ULIST_LABEL_COLUMN,
		     NULL);
	    gtk_tree_view_append_column (GTK_TREE_VIEW (browser), column);

	    bbox = gtk_scrolled_window_new (NULL, NULL);
	    gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (bbox),
						 GTK_SHADOW_IN);
	    gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (bbox),
					    GTK_POLICY_NEVER,
					    GTK_POLICY_AUTOMATIC);
	    gtk_container_add (GTK_CONTAINER (bbox), browser);
	
	    height = size_of_users + 4 /* some padding */;
	    if (height > gdm_wm_screen.height * 0.25)
		    height = gdm_wm_screen.height * 0.25;

	    gtk_widget_set_size_request (GTK_WIDGET (bbox), -1, height);
    }

    if (GdmLogo != NULL) {
	    pb = gdk_pixbuf_new_from_file (GdmLogo, NULL);
    } else {
	    pb = NULL;
    }

    if (pb != NULL) {
	    have_logo = TRUE;
	    logo_image = gtk_image_new_from_pixbuf (pb);
	    lw = gdk_pixbuf_get_width (pb);
	    lh = gdk_pixbuf_get_height (pb);
	    g_object_unref (G_OBJECT (pb));
    } else {
	    logo_image = gtk_image_new ();
	    lw = lh = 100;
    }

    /* this will make the logo always left justified */
    logo_frame = gtk_alignment_new (0, 0.5, 0, 0);
    gtk_widget_show (logo_frame);

    frame = gtk_frame_new (NULL);
    gtk_widget_show (frame);
    gtk_frame_set_shadow_type (GTK_FRAME (frame),
			       GTK_SHADOW_IN);

    ebox = gtk_event_box_new ();
    gtk_widget_show (ebox);
    gtk_container_add (GTK_CONTAINER (ebox), logo_image);
    gtk_container_add (GTK_CONTAINER (frame), ebox);
    gtk_container_add (GTK_CONTAINER (logo_frame), frame);

    if (lw > gdm_wm_screen.width / 2)
	    lw = gdm_wm_screen.width / 2;
    else
	    lw = -1;
    if (lh > (2 * gdm_wm_screen.height) / 3)
	    lh = (2 * gdm_wm_screen.height) / 3;
    else
	    lh = -1;
    if (lw > -1 || lh > -1)
	    gtk_widget_set_size_request (logo_image, lw, lh);
    gtk_widget_show (GTK_WIDGET (logo_image));

    stack = gtk_table_new (7, 1, FALSE);
    gtk_widget_ref (stack);
    g_object_set_data_full (G_OBJECT (login), "stack", stack,
			    (GDestroyNotify) gtk_widget_unref);
    gtk_widget_show (stack);

    greeting = gdm_parse_enriched_string ("<big><big><big>", GdmWelcome, "</big></big></big>");    
    welcome = gtk_label_new (NULL);
    gtk_label_set_markup (GTK_LABEL (welcome), greeting);
    gtk_widget_set_name (welcome, "Welcome");
    g_free (greeting);
    gtk_widget_ref (welcome);
    g_object_set_data_full (G_OBJECT (login), "welcome", welcome,
			    (GDestroyNotify) gtk_widget_unref);
    gtk_widget_show (welcome);
    gtk_table_attach (GTK_TABLE (stack), welcome, 0, 1, 0, 1,
		      (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
		      (GtkAttachOptions) (GTK_EXPAND | GTK_FILL), 0, 0);

    /* Put in error box here */

    err_box = gtk_label_new (0);
    gtk_widget_set_name (err_box, "Error box");
    g_signal_connect (G_OBJECT (err_box), "destroy",
		      G_CALLBACK (gtk_widget_destroyed),
		      &err_box);
    gtk_label_set_line_wrap (GTK_LABEL (err_box), TRUE);
    gtk_table_attach (GTK_TABLE (stack), err_box, 0, 1, 1, 2,
		      (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
		      (GtkAttachOptions) (GTK_FILL), 0, 0);


    hline1 = gtk_hseparator_new ();
    gtk_widget_ref (hline1);
    g_object_set_data_full (G_OBJECT (login), "hline1", hline1,
			    (GDestroyNotify) gtk_widget_unref);
    gtk_widget_show (hline1);
    gtk_table_attach (GTK_TABLE (stack), hline1, 0, 1, 2, 3,
		      (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
		      (GtkAttachOptions) (GTK_FILL), 0, 6);
    
    label = gtk_label_new_with_mnemonic (_("_Username:"));
    gtk_widget_ref (label);
    g_object_set_data_full (G_OBJECT (login), "label", label,
			    (GDestroyNotify) gtk_widget_unref);
    gtk_widget_show (label);
    gtk_table_attach (GTK_TABLE (stack), label, 0, 1, 3, 4,
		      (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
		      (GtkAttachOptions) (0), 0, 0);
    gtk_label_set_justify (GTK_LABEL (label), GTK_JUSTIFY_LEFT);
    gtk_misc_set_alignment (GTK_MISC (label), 0, 0.5);
    gtk_misc_set_padding (GTK_MISC (label), 10, 5);
    gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
    
    entry = gtk_entry_new ();
    g_signal_connect (G_OBJECT (entry), "key_press_event",
		      G_CALLBACK (key_press_event), NULL);
    if (GdmUseCirclesInEntry)
	    gtk_entry_set_invisible_char (GTK_ENTRY (entry), 0x25cf);
    gtk_entry_set_max_length (GTK_ENTRY (entry), 32);
    gtk_widget_set_size_request (entry, 250, -1);
    gtk_widget_ref (entry);
    g_object_set_data_full (G_OBJECT (login), "entry", entry,
			    (GDestroyNotify) gtk_widget_unref);
    gtk_entry_set_text (GTK_ENTRY (entry), "");
    gtk_widget_show (entry);
    gtk_table_attach (GTK_TABLE (stack), entry, 0, 1, 4, 5,
		      (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
		      (GtkAttachOptions) (0), 10, 0);
    g_signal_connect (G_OBJECT(entry), "activate", 
		      G_CALLBACK (gdm_login_enter),
		      NULL);

    /* cursor blinking is evil on remote displays, don't do it forever */
    gdm_setup_blinking ();
    gdm_setup_blinking_entry (entry);
    
    hline2 = gtk_hseparator_new ();
    gtk_widget_ref (hline2);
    g_object_set_data_full (G_OBJECT (login), "hline2", hline2,
			    (GDestroyNotify) gtk_widget_unref);
    gtk_widget_show (hline2);
    gtk_table_attach (GTK_TABLE (stack), hline2, 0, 1, 5, 6,
		      (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
		      (GtkAttachOptions) (GTK_FILL), 0, 10);

    /* I think I'll add the buttons next to this */
    msg = gtk_label_new (_("Please enter your username"));
    gtk_widget_set_name(msg, "Message");
    gtk_label_set_line_wrap (GTK_LABEL (msg), TRUE);
    gtk_label_set_justify (GTK_LABEL (msg), GTK_JUSTIFY_LEFT);
    
    gtk_widget_ref (msg);
    g_object_set_data_full (G_OBJECT (login), "msg", msg,
			    (GDestroyNotify) gtk_widget_unref);
    gtk_widget_show (msg);

    /* FIXME: No Documentation yet.... */
    /*help_button = gtk_button_new_from_stock (GTK_STOCK_OK);
    GTK_WIDGET_UNSET_FLAGS (help_button, GTK_CAN_FOCUS);
    gtk_widget_show (help_button);*/

    ok_button = gtk_button_new_from_stock (GTK_STOCK_OK);
    GTK_WIDGET_UNSET_FLAGS (ok_button, GTK_CAN_FOCUS);
    g_signal_connect (G_OBJECT (ok_button), "clicked",
		      G_CALLBACK (gdm_login_ok_button_press),
		      entry);
    gtk_widget_show (ok_button);

    button_box = gtk_hbox_new (0, 5);
    gtk_box_pack_start (GTK_BOX (button_box), GTK_WIDGET (msg),
			FALSE /* expand */, TRUE /* fill */, 0);
    /*gtk_box_pack_start (GTK_BOX (button_box), GTK_WIDGET (help_button),
			FALSE, FALSE, 0);*/
    gtk_box_pack_end (GTK_BOX (button_box), GTK_WIDGET (ok_button),
		      FALSE, FALSE, 0);
    gtk_widget_show (button_box);
    
    gtk_table_attach (GTK_TABLE (stack), button_box, 0, 1, 6, 7,
		      (GtkAttachOptions) (GTK_FILL),
		      (GtkAttachOptions) (GTK_FILL), 10, 10);

    /* Put it nicely together */

    if (bbox != NULL) {
	    gtk_table_attach (GTK_TABLE (table), bbox, 0, 2, 0, 1,
			      (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
			      (GtkAttachOptions) (GTK_EXPAND | GTK_FILL), 0, 0);
	    gtk_table_attach (GTK_TABLE (table), logo_frame, 0, 1, 1, 2,
			      (GtkAttachOptions) (GTK_FILL),
			      (GtkAttachOptions) (0), 0, 0);
	    gtk_table_attach (GTK_TABLE (table), stack, 1, 2, 1, 2,
			      (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
			      (GtkAttachOptions) (GTK_FILL), 0, 0);
    } else {
	    gtk_table_attach (GTK_TABLE (table), logo_frame, 0, 1, 0, 1,
			      (GtkAttachOptions) (0),
			      (GtkAttachOptions) (0), 0, 0);
	    gtk_table_attach (GTK_TABLE (table), stack, 1, 2, 0, 1,
			      (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
			      (GtkAttachOptions) (GTK_FILL), 0, 0);
    }
    
    gtk_widget_grab_focus (entry);	
    gtk_window_set_focus (GTK_WINDOW (login), entry);	
    g_object_set (G_OBJECT (login),
		  "allow_grow", TRUE,
		  "allow_shrink", TRUE,
		  "resizable", TRUE,
		  NULL);
    
    /* do it now, and we'll also do it later */
    if (GdmSetPosition) {
	    set_screen_pos (login, GdmPositionX, GdmPositionY);
    } else {
	    gdm_wm_center_window (GTK_WINDOW (login));
    }

    g_signal_connect (G_OBJECT (login), "focus_in_event", 
		      G_CALLBACK (gdm_login_focus_in),
		      NULL);
    g_signal_connect (G_OBJECT (login), "focus_out_event", 
		      G_CALLBACK (gdm_login_focus_out),
		      NULL);

    gtk_label_set_mnemonic_widget (GTK_LABEL (label), entry);

    /* normally disable the prompt first */
    if ( ! DOING_GDM_DEVELOPMENT) {
	    gtk_widget_set_sensitive (entry, FALSE);
	    gtk_widget_set_sensitive (ok_button, FALSE);
    }

    gtk_widget_show_all (GTK_WIDGET (login));
    if ( ! have_logo) {
	    gtk_table_set_col_spacings (GTK_TABLE (table), 0);
	    gtk_widget_hide (logo_frame);
    }
}


static gint 
gdm_login_sort_func (gpointer d1, gpointer d2)
{
    GdmLoginUser *a = d1;
    GdmLoginUser *b = d2;

    if (!d1 || !d2)
	return (0);

    return (strcmp (a->login, b->login));
}


static GdmLoginUser * 
gdm_login_user_alloc (const gchar *logname, uid_t uid, const gchar *homedir,
		      const char *gecos)
{
	GdmLoginUser *user;
	GdkPixbuf *img = NULL;
	gchar buf[PIPE_SIZE];
	size_t size;
	int bufsize;
	char *p;

	user = g_new0 (GdmLoginUser, 1);

	user->uid = uid;
	user->login = g_strdup (logname);
	if (!g_utf8_validate (gecos, -1, NULL))
		user->gecos = ve_locale_to_utf8 (gecos);
	else
		user->gecos = g_strdup (gecos);

	/* Cut up to first comma since those are ugly arguments and
	 * not the name anymore, but only if more then 1 comma is found,
	 * since otherwise it might be part of the actual comment,
	 * this is sort of "heurestic" because there seems to be no
	 * real standard, it's all optional */
	p = strchr (user->gecos, ',');
	if (p != NULL) {
		if (strchr (p+1, ',') != NULL)
			*p = '\0';
	}

	user->homedir = g_strdup (homedir);
	if (defface != NULL)
		user->picture = (GdkPixbuf *)g_object_ref (G_OBJECT (defface));

	if (ve_string_empty (logname))
		return user;

	/* don't read faces, since that requires the daemon */
	if (DOING_GDM_DEVELOPMENT)
		return user;

	/* read initial request */
	do {
		while (read (STDIN_FILENO, buf, 1) == 1)
			if (buf[0] == STX)
				break;
		size = read (STDIN_FILENO, buf, sizeof (buf));
		if (size <= 0)
			return user;
	} while (buf[0] != GDM_NEEDPIC);

	printf ("%c%s\n", STX, logname);
	fflush (stdout);

	do {
		while (read (STDIN_FILENO, buf, 1) == 1)
			if (buf[0] == STX)
				break;
		size = read (STDIN_FILENO, buf, sizeof (buf));
		if (size <= 0)
			return user;
	} while (buf[0] != GDM_READPIC);

	/* both nul terminate and wipe the trailing \n */
	buf[size-1] = '\0';

	if (size < 2) {
		img = NULL;
	} else if (sscanf (&buf[1], "buffer:%d", &bufsize) == 1) {
		char buffer[2048];
		int pos = 0;
		int n;
		GdkPixbufLoader *loader;
		/* we trust the daemon, even if it wanted to give us
		 * bogus bufsize */
		/* the daemon will now print the buffer */
		printf ("%cOK\n", STX);
		fflush (stdout);

		while (read (STDIN_FILENO, buf, 1) == 1)
			if (buf[0] == STX)
				break;

		loader = gdk_pixbuf_loader_new ();

		while ((n = read (STDIN_FILENO, buffer,
				  MIN (sizeof (buffer), bufsize-pos))) > 0) {
			gdk_pixbuf_loader_write (loader, buffer, n, NULL);
			pos += n;
			if (pos >= bufsize)
			       break;	
		}

		gdk_pixbuf_loader_close (loader, NULL);

		img = gdk_pixbuf_loader_get_pixbuf (loader);
		if (img != NULL)
			g_object_ref (G_OBJECT (img));

		g_object_unref (G_OBJECT (loader));

		/* read the "done" bit, but don't check */
		read (STDIN_FILENO, buf, sizeof (buf));
	} else if (access (&buf[1], R_OK) == 0) {
		img = gdk_pixbuf_new_from_file (&buf[1], NULL);
	} else {
		img = NULL;
	}

	/* the daemon is now free to go on */
	printf ("%c\n", STX);
	fflush (stdout);

	if (img != NULL) {
		gint w, h;

		w = gdk_pixbuf_get_width (img);
		h = gdk_pixbuf_get_height (img);

		if (w > h && w > GdmIconMaxWidth) {
			h = h * ((gfloat) GdmIconMaxWidth/w);
			w = GdmIconMaxWidth;
		} else if (h > GdmIconMaxHeight) {
			w = w * ((gfloat) GdmIconMaxHeight/h);
			h = GdmIconMaxHeight;
		}

		if (user->picture != NULL)
			g_object_unref (G_OBJECT (user->picture));

		maxwidth = MAX (maxwidth, w);
		maxheight = MAX (maxheight, h);
		if (w != gdk_pixbuf_get_width (img) ||
		    h != gdk_pixbuf_get_height (img)) {
			user->picture = gdk_pixbuf_scale_simple
				(img, w, h, GDK_INTERP_BILINEAR);
			g_object_unref (G_OBJECT (img));
		} else {
			user->picture = img;
		}
	}

	return user;
}


static gboolean
gdm_login_check_exclude (struct passwd *pwent)
{
	const char * const lockout_passes[] = { "!!", NULL };
	gint i;

	if ( ! GdmAllowRoot && pwent->pw_uid == 0)
		return TRUE;

	if ( ! GdmAllowRemoteRoot && ! login_is_local && pwent->pw_uid == 0)
		return TRUE;

	if (pwent->pw_uid < GdmMinimalUID)
		return TRUE;

	for (i=0 ; lockout_passes[i] != NULL ; i++)  {
		if (strcmp (lockout_passes[i], pwent->pw_passwd) == 0) {
			return TRUE;
		}
	}

	if (GdmExclude != NULL &&
	    GdmExclude[0] != '\0') {
		char **excludes;
		excludes = g_strsplit (GdmExclude, ",", 0);

		for (i=0 ; excludes[i] != NULL ; i++)  {
			g_strstrip (excludes[i]);
			if (g_ascii_strcasecmp (excludes[i],
						pwent->pw_name) == 0) {
				g_strfreev (excludes);
				return TRUE;
			}
		}
		g_strfreev (excludes);
	}

	return FALSE;
}


static gboolean
gdm_login_check_shell (const gchar *usersh)
{
    gint found = 0;
    gchar *csh;

    setusershell ();

    while ((csh = getusershell ()) != NULL)
	if (! strcmp (csh, usersh))
	    found = 1;

    endusershell ();

    return (found);
}


static void 
gdm_login_users_init (void)
{
    GdmLoginUser *user;
    struct passwd *pwent;
    time_t time_started;

    if (access (GdmDefaultFace, R_OK)) {
	    syslog (LOG_WARNING,
		    _("Can't open DefaultImage: %s. Suspending face browser!"),
		    GdmDefaultFace);
	    GdmBrowser = FALSE;
	    return;
    } else  {
	    defface = gdk_pixbuf_new_from_file (GdmDefaultFace, NULL);
    }

    time_started = time (NULL);

    setpwent ();

    pwent = getpwent();
	
    while (pwent != NULL) {

	/* FIXME: fix properly, see bug #111830 */
	if (number_of_users > 500 ||
	    time_started + 5 <= time (NULL)) {
		user = gdm_login_user_alloc ("",
					     9999 /*fake uid*/,
					     "/",
					     _("Too many users to list here..."));
		users = g_list_insert_sorted (users, user,
					      (GCompareFunc) gdm_login_sort_func);
		/* don't update the size numbers, it's ok if this "user" is
		   offscreen */
		break;
	}
	
	if (pwent->pw_shell && 
	    gdm_login_check_shell (pwent->pw_shell) &&
	    !gdm_login_check_exclude (pwent)) {

	    user = gdm_login_user_alloc(pwent->pw_name,
					pwent->pw_uid,
					pwent->pw_dir,
					ve_sure_string (pwent->pw_gecos));

	    if ((user) &&
		(! g_list_find_custom (users, user, (GCompareFunc) gdm_login_sort_func))) {
		users = g_list_insert_sorted(users, user,
					     (GCompareFunc) gdm_login_sort_func);
		number_of_users ++;
		if (user->picture != NULL) {
			size_of_users +=
				gdk_pixbuf_get_height (user->picture) + 2;
		} else {
			size_of_users += GdmIconMaxHeight;
		}
	    }
	}
	
	pwent = getpwent();
    }

    endpwent ();
}

static void
set_root (GdkPixbuf *pb)
{
	GdkPixmap *pm;

	g_return_if_fail (pb != NULL);

	gdk_pixbuf_render_pixmap_and_mask (pb,
					   &pm,
					   NULL /* mask_return */,
					   0 /* alpha_threshold */);

	/* paranoia */
	if (pm == NULL)
		return;

	gdk_error_trap_push ();

	gdk_window_set_back_pixmap (gdk_get_default_root_window (),
				    pm,
				    FALSE /* parent_relative */);

	g_object_unref (G_OBJECT (pm));

	gdk_window_clear (gdk_get_default_root_window ());

	gdk_flush ();
	gdk_error_trap_pop ();
}

static GdkPixbuf *
render_scaled_back (const GdkPixbuf *pb)
{
	int i;
	int width, height;

	GdkPixbuf *back = gdk_pixbuf_new (GDK_COLORSPACE_RGB,
					  gdk_pixbuf_get_has_alpha (pb),
					  8,
					  gdk_screen_width (),
					  gdk_screen_height ());

	width = gdk_pixbuf_get_width (pb);
	height = gdk_pixbuf_get_height (pb);

	for (i = 0; i < gdm_wm_screens; i++) {
		gdk_pixbuf_scale (pb, back,
				  gdm_wm_allscreens[i].x,
				  gdm_wm_allscreens[i].y,
				  gdm_wm_allscreens[i].width,
				  gdm_wm_allscreens[i].height,
				  gdm_wm_allscreens[i].x /* offset_x */,
				  gdm_wm_allscreens[i].y /* offset_y */,
				  (double) gdm_wm_allscreens[i].width / width,
				  (double) gdm_wm_allscreens[i].height / height,
				  GDK_INTERP_BILINEAR);
	}

	return back;
}

static void
add_color_to_pb (GdkPixbuf *pb, GdkColor *color)
{
	int width = gdk_pixbuf_get_width (pb);
	int height = gdk_pixbuf_get_height (pb);
	int rowstride = gdk_pixbuf_get_rowstride (pb);
	guchar *pixels = gdk_pixbuf_get_pixels (pb);
	gboolean has_alpha = gdk_pixbuf_get_has_alpha (pb);
	int i;
	int cr = color->red >> 8;
	int cg = color->green >> 8;
	int cb = color->blue >> 8;

	if ( ! has_alpha)
		return;

	for (i = 0; i < height; i++) {
		int ii;
		guchar *p = pixels + (rowstride * i);
		for (ii = 0; ii < width; ii++) {
			int r = p[0];
			int g = p[1];
			int b = p[2];
			int a = p[3];

			p[0] = (r * a + cr * (255 - a)) >> 8;
			p[1] = (g * a + cg * (255 - a)) >> 8;
			p[2] = (b * a + cb * (255 - a)) >> 8;
			p[3] = 255;

			p += 4;
		}
	}
}

/* setup background color/image */
static void
setup_background (void)
{
	GdkColor color;
	GdkPixbuf *pb = NULL;

	if (GdmBackgroundType == GDM_BACKGROUND_IMAGE &&
	    ! ve_string_empty (GdmBackgroundImage))
		pb = gdk_pixbuf_new_from_file (GdmBackgroundImage, NULL);

	/* Load background image */
	if (pb != NULL) {
		if (gdk_pixbuf_get_has_alpha (pb)) {
			if (GdmBackgroundColor == NULL ||
			    GdmBackgroundColor[0] == '\0' ||
			    ! gdk_color_parse (GdmBackgroundColor,
					       &color)) {
				gdk_color_parse ("#007777", &color);
			}
			add_color_to_pb (pb, &color);
		}
		if (GdmBackgroundScaleToFit) {
			GdkPixbuf *spb = render_scaled_back (pb);
			g_object_unref (G_OBJECT (pb));
			pb = spb;
		}

		/* paranoia */
		if (pb != NULL) {
			set_root (pb);
			g_object_unref (G_OBJECT (pb));
		}
	/* Load background color */
	} else if (GdmBackgroundType != GDM_BACKGROUND_NONE) {
		GdkColormap *colormap;

		if (GdmBackgroundColor == NULL ||
		    GdmBackgroundColor[0] == '\0' ||
		    ! gdk_color_parse (GdmBackgroundColor, &color)) {
			gdk_color_parse ("#007777", &color);
		}

		colormap = gdk_drawable_get_colormap
			(gdk_get_default_root_window ());
		/* paranoia */
		if (colormap != NULL) {
			gboolean success;
			gdk_error_trap_push ();

			gdk_colormap_alloc_colors (colormap, &color, 1,
						   FALSE, TRUE, &success);
			gdk_window_set_background (gdk_get_default_root_window (), &color);
			gdk_window_clear (gdk_get_default_root_window ());

			gdk_flush ();
			gdk_error_trap_pop ();
		}
	}
}


/* Load the background stuff, the image and program */
static void
run_backgrounds (void)
{
	setup_background ();

	/* Launch a background program if one exists */
	if ((GdmBackgroundType == GDM_BACKGROUND_NONE ||
	     GdmRunBackgroundProgAlways) &&
	    ! ve_string_empty (GdmBackgroundProg)) {
		backgroundpid = gdm_run_command (GdmBackgroundProg);
		g_atexit (gdm_kill_thingies);
	}
}

enum {
	RESPONSE_RESTART,
	RESPONSE_REBOOT,
	RESPONSE_CLOSE
};

static gboolean
gdm_reread_config (int sig, gpointer data)
{
	char *str;
	VeConfig *config;
	gboolean resize = FALSE;
	/* reparse config stuff here.  At least ones we care about */

	config = ve_config_get (GDM_CONFIG_FILE);

	/* FIXME: The following is evil, we should update on the fly rather
	 * then just restarting */
	/* Also we may not need to check ALL those keys but just a few */
	if ( ! gdm_common_string_same (config, GdmGtkRC, GDM_KEY_GTKRC) ||
	     ! gdm_common_string_same (config, GdmGtkTheme, GDM_KEY_GTK_THEME) ||
	     ! gdm_common_string_same (config, GdmInfoMsgFile, GDM_KEY_INFO_MSG_FILE) ||
	     ! gdm_common_string_same (config, GdmInfoMsgFont, GDM_KEY_INFO_MSG_FONT) ||
	     ! gdm_common_int_same (config,
			 GdmXineramaScreen, GDM_KEY_XINERAMASCREEN) ||
	     ! gdm_common_bool_same (config, GdmSystemMenu, GDM_KEY_SYSMENU) ||
	     ! gdm_common_bool_same (config, GdmBrowser, GDM_KEY_BROWSER) ||
	     ! gdm_common_bool_same (config, GdmConfigAvailable, GDM_KEY_CONFIG_AVAILABLE) ||
	     ! gdm_common_bool_same (config, GdmChooserButton, GDM_KEY_CHOOSER_BUTTON) ||
	     ! gdm_common_bool_same (config, GdmTimedLoginEnable, GDM_KEY_TIMED_LOGIN_ENABLE)) {
		/* Set busy cursor */
		gdm_common_setup_cursor (GDK_WATCH);

		gdm_wm_save_wm_order ();

		gdm_kill_thingies ();
		_exit (DISPLAY_RESTARTGREETER);
		return TRUE;
	}

	if ( ! gdm_common_string_same (config, GdmBackgroundImage, GDM_KEY_BACKGROUNDIMAGE) ||
	     ! gdm_common_string_same (config, GdmBackgroundColor, GDM_KEY_BACKGROUNDCOLOR) ||
	     ! gdm_common_int_same (config, GdmBackgroundType, GDM_KEY_BACKGROUNDTYPE) ||
	     ! gdm_common_bool_same (config,
			  GdmBackgroundScaleToFit,
			  GDM_KEY_BACKGROUNDSCALETOFIT) ||
	     ! gdm_common_bool_same (config,
			  GdmBackgroundRemoteOnlyColor,
			  GDM_KEY_BACKGROUNDREMOTEONLYCOLOR)) {
		GdmBackgroundImage = ve_config_get_string (config, GDM_KEY_BACKGROUNDIMAGE);
		GdmBackgroundColor = ve_config_get_string (config, GDM_KEY_BACKGROUNDCOLOR);
		GdmBackgroundType = ve_config_get_int (config, GDM_KEY_BACKGROUNDTYPE);
		GdmBackgroundScaleToFit = ve_config_get_bool (config, GDM_KEY_BACKGROUNDSCALETOFIT);
		GdmBackgroundRemoteOnlyColor = ve_config_get_bool (config, GDM_KEY_BACKGROUNDREMOTEONLYCOLOR);

		if (GdmBackgroundType != GDM_BACKGROUND_NONE &&
		    ! GdmRunBackgroundProgAlways)
			gdm_kill_thingies ();

		setup_background ();

		/* Launch a background program if one exists */
		if ((GdmBackgroundType == GDM_BACKGROUND_NONE ||
		     GdmRunBackgroundProgAlways) &&
		    ! ve_string_empty (GdmBackgroundProg)) {
			backgroundpid = gdm_run_command (GdmBackgroundProg);
		}
	}

	GdmSoundProgram = ve_config_get_string (config, GDM_KEY_SOUND_PROGRAM);
	GdmSoundOnLogin = ve_config_get_bool (config, GDM_KEY_SOUND_ON_LOGIN);
	GdmSoundOnLoginFile = ve_config_get_string (config, GDM_KEY_SOUND_ON_LOGIN_FILE);

	GdmUse24Clock = ve_config_get_bool (config, GDM_KEY_USE_24_CLOCK);
	update_clock (NULL);

	str = ve_config_get_string (config, GDM_KEY_LOGO);
	if (strcmp (ve_sure_string (str), ve_sure_string (GdmLogo)) != 0) {
		GdkPixbuf *pb;
		gboolean have_logo = FALSE;
		int lw, lh;

		g_free (GdmLogo);
		GdmLogo = str;

		if (GdmLogo != NULL) {
			pb = gdk_pixbuf_new_from_file (GdmLogo, NULL);
		} else {
			pb = NULL;
		}

		if (pb != NULL) {
			have_logo = TRUE;
			gtk_image_set_from_pixbuf (GTK_IMAGE (logo_image), pb);
			lw = gdk_pixbuf_get_width (pb);
			lh = gdk_pixbuf_get_height (pb);
			g_object_unref (G_OBJECT (pb));
		} else {
			lw = lh = 100;
		}

		if (lw > gdm_wm_screen.width / 2)
			lw = gdm_wm_screen.width / 2;
		else
			lw = -1;
		if (lh > (2 * gdm_wm_screen.height) / 3)
			lh = (2 * gdm_wm_screen.height) / 3;
		else
			lh = -1;
		if (lw > -1 || lh > -1)
			gtk_widget_set_size_request (logo_image, lw, lh);

		if (have_logo) {
			gtk_table_set_col_spacings (GTK_TABLE (table), 10);
			gtk_widget_show (logo_frame);
		} else {
			gtk_table_set_col_spacings (GTK_TABLE (table), 0);
			gtk_widget_hide (logo_frame);
		}

		resize = TRUE;
	} else {
		g_free (str);
	}

	str = ve_config_get_translated_string (config, greeter_Welcome_key);
	/* A hack */
	if (strcmp (ve_sure_string (str), "Welcome") == 0) {
		g_free (str);
		str = g_strdup (_("Welcome"));
	} else if (strcmp (ve_sure_string (str), "Welcome to %n") == 0) {
		g_free (str);
		str = g_strdup (_("Welcome to %n"));
	}
	if (strcmp (ve_sure_string (str), ve_sure_string (GdmWelcome)) != 0) {
		char *greeting;
		g_free (GdmWelcome);
		GdmWelcome = str;

		greeting = gdm_parse_enriched_string ("<big><big><big>", GdmWelcome, "</big></big></big>");    
		gtk_label_set_markup (GTK_LABEL (welcome), greeting);
		g_free (greeting);

		resize = TRUE;
	} else {
		g_free (str);
	}

	if (resize) {
		login_window_resize (TRUE /* force */);
	}

	return TRUE;
}

int 
main (int argc, char *argv[])
{
    struct sigaction hup;
    struct sigaction term;
    sigset_t mask;
    GIOChannel *ctrlch;
    const char *gdm_version;
    const char *gdm_protocol_version;

    if (g_getenv ("DOING_GDM_DEVELOPMENT") != NULL)
	    DOING_GDM_DEVELOPMENT = TRUE;

    openlog ("gdmlogin", LOG_PID, LOG_DAEMON);

    bindtextdomain (GETTEXT_PACKAGE, GNOMELOCALEDIR);
    bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
    textdomain (GETTEXT_PACKAGE);

    gtk_init (&argc, &argv);

    /* Should be a watch already, but just in case */
    gdm_common_setup_cursor (GDK_WATCH);

    gdm_login_parse_config ();

    setlocale (LC_ALL, "");

    tooltips = gtk_tooltips_new ();

    gdm_wm_screen_init (GdmXineramaScreen);

    gdm_version = g_getenv ("GDM_VERSION");
    gdm_protocol_version = g_getenv ("GDM_GREETER_PROTOCOL_VERSION");

    if ( ! DOING_GDM_DEVELOPMENT &&
	 ((gdm_protocol_version != NULL &&
	   strcmp (gdm_protocol_version, GDM_GREETER_PROTOCOL_VERSION) != 0) ||
	  (gdm_protocol_version == NULL &&
	   (gdm_version == NULL ||
	    strcmp (gdm_version, VERSION) != 0))) &&
	 ve_string_empty (g_getenv ("GDM_IS_LOCAL"))) {
	    GtkWidget *dialog;

	    gdm_wm_init (0);

	    gdm_wm_focus_new_windows (TRUE);

	    dialog = ve_hig_dialog_new (NULL /* parent */,
					GTK_DIALOG_MODAL /* flags */,
					GTK_MESSAGE_ERROR,
					GTK_BUTTONS_OK,
					FALSE /* markup */,
					_("Cannot start the greeter"),
					_("The greeter version (%s) does not match the daemon "
					  "version.  "
					  "You have probably just upgraded gdm.  "
					  "Please restart the gdm daemon or reboot the computer."),
					VERSION);

	    gtk_widget_show_all (dialog);
	    gdm_wm_center_window (GTK_WINDOW (dialog));

	    gdm_common_setup_cursor (GDK_LEFT_PTR);

	    gtk_dialog_run (GTK_DIALOG (dialog));

	    return EXIT_SUCCESS;
    }

    if ( ! DOING_GDM_DEVELOPMENT &&
	gdm_protocol_version == NULL &&
	gdm_version == NULL) {
	    GtkWidget *dialog;

	    gdm_wm_init (0);

	    gdm_wm_focus_new_windows (TRUE);

	    dialog = ve_hig_dialog_new (NULL /* parent */,
					GTK_DIALOG_MODAL /* flags */,
					GTK_MESSAGE_WARNING,
					GTK_BUTTONS_NONE,
					FALSE /* markup */,
					_("Cannot start the greeter"),
					_("The greeter version (%s) does not match the daemon "
					  "version.  "
					  "You have probably just upgraded gdm.  "
					  "Please restart the gdm daemon or reboot the computer."),
					VERSION);
	    gtk_dialog_add_buttons (GTK_DIALOG (dialog),
				    _("Reboot"),
				    RESPONSE_REBOOT,
				    GTK_STOCK_CLOSE,
				    RESPONSE_CLOSE,
				    NULL);

	    gtk_widget_show_all (dialog);
	    gdm_wm_center_window (GTK_WINDOW (dialog));

	    gdm_common_setup_cursor (GDK_LEFT_PTR);

	    switch (gtk_dialog_run (GTK_DIALOG (dialog))) {
	    case RESPONSE_REBOOT:
		    gtk_widget_destroy (dialog);
		    return DISPLAY_REBOOT;
	    default:
		    gtk_widget_destroy (dialog);
		    return DISPLAY_ABORT;
	    }
    }

    if ( ! DOING_GDM_DEVELOPMENT &&
	 ((gdm_protocol_version != NULL &&
	   strcmp (gdm_protocol_version, GDM_GREETER_PROTOCOL_VERSION) != 0) ||
	  (gdm_protocol_version == NULL &&
	   strcmp (gdm_version, VERSION) != 0))) {
	    GtkWidget *dialog;

	    gdm_wm_init (0);

	    gdm_wm_focus_new_windows (TRUE);

	    dialog = ve_hig_dialog_new (NULL /* parent */,
					GTK_DIALOG_MODAL /* flags */,
					GTK_MESSAGE_WARNING,
					GTK_BUTTONS_NONE,
					FALSE /* markup */,
					_("Cannot start the greeter"),
					_("The greeter version (%s) does not match the daemon "
					  "version (%s).  "
					  "You have probably just upgraded gdm.  "
					  "Please restart the gdm daemon or reboot the computer."),
					VERSION, gdm_version);
	    gtk_dialog_add_buttons (GTK_DIALOG (dialog),
				    _("Restart"),
				    RESPONSE_RESTART,
				    _("Reboot"),
				    RESPONSE_REBOOT,
				    GTK_STOCK_CLOSE,
				    RESPONSE_CLOSE,
				    NULL);


	    gtk_widget_show_all (dialog);
	    gdm_wm_center_window (GTK_WINDOW (dialog));

	    gtk_dialog_set_default_response (GTK_DIALOG (dialog), RESPONSE_RESTART);

	    gdm_common_setup_cursor (GDK_LEFT_PTR);

	    switch (gtk_dialog_run (GTK_DIALOG (dialog))) {
	    case RESPONSE_RESTART:
		    gtk_widget_destroy (dialog);
		    return DISPLAY_RESTARTGDM;
	    case RESPONSE_REBOOT:
		    gtk_widget_destroy (dialog);
		    return DISPLAY_REBOOT;
	    default:
		    gtk_widget_destroy (dialog);
		    return DISPLAY_ABORT;
	    }
    }

    if (GdmBrowser)
	gdm_login_users_init ();

    gdm_login_gui_init ();

    if (GdmBrowser)
	gdm_login_browser_populate ();

    ve_signal_add (SIGHUP, gdm_reread_config, NULL);

    hup.sa_handler = ve_signal_notify;
    hup.sa_flags = 0;
    sigemptyset(&hup.sa_mask);
    sigaddset (&hup.sa_mask, SIGCHLD);

    if G_UNLIKELY (sigaction (SIGHUP, &hup, NULL) < 0) 
        gdm_common_abort (_("%s: Error setting up %s signal handler: %s"), "main", "HUP", strerror (errno));

    term.sa_handler = gdm_login_done;
    term.sa_flags = 0;
    sigemptyset(&term.sa_mask);
    sigaddset (&term.sa_mask, SIGCHLD);

    if G_UNLIKELY (sigaction (SIGINT, &term, NULL) < 0) 
        gdm_common_abort (_("%s: Error setting up %s signal handler: %s"), "main", "INT", strerror (errno));

    if G_UNLIKELY (sigaction (SIGTERM, &term, NULL) < 0) 
        gdm_common_abort (_("%s: Error setting up %s signal handler: %s"), "main", "TERM", strerror (errno));

    sigemptyset (&mask);
    sigaddset (&mask, SIGTERM);
    sigaddset (&mask, SIGHUP);
    sigaddset (&mask, SIGINT);
    
    if G_UNLIKELY (sigprocmask (SIG_UNBLOCK, &mask, NULL) == -1) 
	gdm_common_abort (_("Could not set signal mask!"));

    /* ignore SIGCHLD */
    sigemptyset (&mask);
    sigaddset (&mask, SIGCHLD);
    
    if G_UNLIKELY (sigprocmask (SIG_BLOCK, &mask, NULL) == -1) 
	gdm_common_abort (_("Could not set signal mask!"));

    run_backgrounds ();

    if G_LIKELY ( ! DOING_GDM_DEVELOPMENT) {
	    ctrlch = g_io_channel_unix_new (STDIN_FILENO);
	    g_io_channel_set_encoding (ctrlch, NULL, NULL);
	    g_io_channel_set_buffered (ctrlch, FALSE);
	    g_io_add_watch (ctrlch, 
			    G_IO_IN | G_IO_PRI | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			    (GIOFunc) gdm_login_ctrl_handler,
			    NULL);
	    g_io_channel_unref (ctrlch);
    }

    /* if in timed mode, delay timeout on keyboard or menu
     * activity */
    if ( ! ve_string_empty (GdmTimedLogin)) {
	    guint sid = g_signal_lookup ("activate",
					 GTK_TYPE_MENU_ITEM);
	    g_signal_add_emission_hook (sid,
					0 /* detail */,
					gdm_timer_up_delay,
					NULL /* data */,
					NULL /* destroy_notify */);

	    sid = g_signal_lookup ("key_press_event",
				   GTK_TYPE_WIDGET);
	    g_signal_add_emission_hook (sid,
					0 /* detail */,
					gdm_timer_up_delay,
					NULL /* data */,
					NULL /* destroy_notify */);

	    sid = g_signal_lookup ("button_press_event",
				   GTK_TYPE_WIDGET);
	    g_signal_add_emission_hook (sid,
					0 /* detail */,
					gdm_timer_up_delay,
					NULL /* data */,
					NULL /* destroy_notify */);
    }

    /* if a flexiserver, reap self after some time */
    if (GdmFlexiReapDelayMinutes > 0 &&
	! ve_string_empty (g_getenv ("GDM_FLEXI_SERVER")) &&
	/* but don't reap Xnest flexis */
	ve_string_empty (g_getenv ("GDM_PARENT_DISPLAY"))) {
	    guint sid = g_signal_lookup ("activate",
					 GTK_TYPE_MENU_ITEM);
	    g_signal_add_emission_hook (sid,
					0 /* detail */,
					delay_reaping,
					NULL /* data */,
					NULL /* destroy_notify */);

	    sid = g_signal_lookup ("key_press_event",
				   GTK_TYPE_WIDGET);
	    g_signal_add_emission_hook (sid,
					0 /* detail */,
					delay_reaping,
					NULL /* data */,
					NULL /* destroy_notify */);

	    sid = g_signal_lookup ("button_press_event",
				   GTK_TYPE_WIDGET);
	    g_signal_add_emission_hook (sid,
					0 /* detail */,
					delay_reaping,
					NULL /* data */,
					NULL /* destroy_notify */);

	    last_reap_delay = time (NULL);
	    g_timeout_add (60*1000, reap_flexiserver, NULL);
    }

    if G_LIKELY (g_getenv ("RUNNING_UNDER_GDM") != NULL) {
	    guint sid = g_signal_lookup ("event",
					 GTK_TYPE_WIDGET);
	    g_signal_add_emission_hook (sid,
					0 /* detail */,
					gdm_event,
					NULL /* data */,
					NULL /* destroy_notify */);
    }

    gtk_widget_queue_resize (login);
    gtk_widget_show_now (login);

    if (GdmSetPosition) {
	    set_screen_pos (login, GdmPositionX, GdmPositionY);
    } else {
	    gdm_wm_center_window (GTK_WINDOW (login));
    }

    /* can it ever happen that it'd be NULL here ??? */
    if G_UNLIKELY (login->window != NULL) {
	    gdm_wm_init (GDK_WINDOW_XWINDOW (login->window));

	    /* Run the focus, note that this will work no matter what
	     * since gdm_wm_init will set the display to the gdk one
	     * if it fails */
	    gdm_wm_focus_window (GDK_WINDOW_XWINDOW (login->window));
    }

    if G_UNLIKELY (session_dir_whacked_out) {
	    GtkWidget *dialog;

	    gdm_wm_focus_new_windows (TRUE);

	    dialog = ve_hig_dialog_new (NULL /* parent */,
					GTK_DIALOG_MODAL /* flags */,
					GTK_MESSAGE_ERROR,
					GTK_BUTTONS_OK,
					FALSE /* markup */,
					_("Session directory is missing"),
					"%s",
					_("Your session directory is missing or empty!  "
					  "There are two available sessions you can use, but "
					  "you should log in and correct the gdm configuration."));
	    gtk_widget_show_all (dialog);
	    gdm_wm_center_window (GTK_WINDOW (dialog));

	    gdm_common_setup_cursor (GDK_LEFT_PTR);

	    gdm_wm_no_login_focus_push ();
	    gtk_dialog_run (GTK_DIALOG (dialog));
	    gtk_widget_destroy (dialog);
	    gdm_wm_no_login_focus_pop ();
    }

    if G_UNLIKELY (g_getenv ("GDM_WHACKED_GREETER_CONFIG") != NULL) {
	    GtkWidget *dialog;

	    gdm_wm_focus_new_windows (TRUE);

	    dialog = ve_hig_dialog_new (NULL /* parent */,
					GTK_DIALOG_MODAL /* flags */,
					GTK_MESSAGE_ERROR,
					GTK_BUTTONS_OK,
					FALSE /* markup */,
					_("Configuration is not correct"),
					"%s",
					_("The configuration file contains an invalid command "
					  "line for the login dialog, and thus I ran the "
					  "default command.  Please fix your configuration."));
	    gtk_widget_show_all (dialog);
	    gdm_wm_center_window (GTK_WINDOW (dialog));

	    gdm_common_setup_cursor (GDK_LEFT_PTR);

	    gdm_wm_no_login_focus_push ();
	    gtk_dialog_run (GTK_DIALOG (dialog));
	    gtk_widget_destroy (dialog);
	    gdm_wm_no_login_focus_pop ();
    }

    /* There was no config file */
    if G_UNLIKELY (used_defaults) {
	    GtkWidget *dialog;

	    gdm_wm_focus_new_windows (TRUE);

	    dialog = ve_hig_dialog_new (NULL /* parent */,
					GTK_DIALOG_MODAL /* flags */,
					GTK_MESSAGE_ERROR,
					GTK_BUTTONS_OK,
					FALSE /* markup */,
					_("No configuration was found"),
					"%s",
					_("The configuration was not found.  GDM is using "
					  "defaults to run this session.  You should log in "
					  "and create a configuration file with the GDM "
					  "configuration program."));
	    gtk_widget_show_all (dialog);
	    gdm_wm_center_window (GTK_WINDOW (dialog));

	    gdm_common_setup_cursor (GDK_LEFT_PTR);

	    gdm_wm_no_login_focus_push ();
	    gtk_dialog_run (GTK_DIALOG (dialog));
	    gtk_widget_destroy (dialog);
	    gdm_wm_no_login_focus_pop ();
    }

    gdm_wm_restore_wm_order ();

    gdm_common_show_info_msg ();

    /* Only setup the cursor now since it will be a WATCH from before */
    gdm_common_setup_cursor (GDK_LEFT_PTR);

    gtk_main ();

    gdm_kill_thingies ();

    return EXIT_SUCCESS;
}

/* EOF */

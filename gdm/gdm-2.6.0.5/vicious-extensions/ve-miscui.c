/* Misc UI routines
 *
 * (c) 2000 Eazel, Inc.
 * (c) 2001 George Lebl
 * (c) 2003 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */
#include <config.h>
#include <libgnome/libgnome.h>
#include <libgnomeui/libgnomeui.h>

#include "ve-misc.h"
#include "ve-miscui.h"

void
ve_entry_set_red (GtkWidget *w, gboolean state)
{
	if (state) {
		GtkStyle *ns;
		GdkColor red = { 0, 65535, 0, 0 };

		ns = gtk_style_copy (w->style);
		g_object_ref (G_OBJECT (ns));

		ns->fg[GTK_STATE_NORMAL] = red;
		ns->text[GTK_STATE_NORMAL] = red;

		gtk_widget_set_style (w, ns);
		g_object_unref (G_OBJECT (ns));

		gtk_widget_queue_draw (w);
	} else {
		gtk_widget_set_style (w, NULL);
	}
}

GtkWidget *
ve_gtk_option_menu_get_item (GtkOptionMenu *option_menu, int index)
{
	g_return_val_if_fail (option_menu != NULL, NULL);
	g_return_val_if_fail (GTK_IS_OPTION_MENU (option_menu), NULL);

	if (option_menu->menu != NULL) {
		return g_list_nth_data (GTK_MENU_SHELL(option_menu->menu)->children,
					index);
	}
	return NULL;
}

/* stolen from gsearchtool */
GtkWidget *
ve_hig_dialog_new (GtkWindow      *parent,
		   GtkDialogFlags flags,
		   GtkMessageType type,
		   GtkButtonsType buttons,
		   gboolean       markup,
		   const gchar    *header,
		   const gchar    *messagefmt,
		   ...)
{
	GtkWidget *dialog;
	GtkWidget *dialog_vbox;
	GtkWidget *dialog_action_area;
	GtkWidget *hbox;
	GtkWidget *vbox;
	GtkWidget *label;
	GtkWidget *button;
	GtkWidget *image;
	gchar     *title;
	va_list args;
	char *msg;
	char *hdr;

	if ( ! ve_string_empty (messagefmt)) {
		va_start (args, messagefmt);
		msg = g_strdup_vprintf (messagefmt, args);
		va_end (args);
	} else {
		msg = NULL;
	}

	if (markup)
		hdr = g_strdup (header);
	else
		hdr = g_markup_escape_text (header, -1);

	dialog = gtk_dialog_new ();
	
	gtk_dialog_set_has_separator (GTK_DIALOG (dialog), FALSE);
	gtk_container_set_border_width (GTK_CONTAINER (dialog), 5);
	gtk_window_set_resizable (GTK_WINDOW (dialog), FALSE);
	gtk_window_set_title (GTK_WINDOW (dialog), "");
  
	dialog_vbox = GTK_DIALOG (dialog)->vbox;
	gtk_box_set_spacing (GTK_BOX (dialog_vbox), 12);

	hbox = gtk_hbox_new (FALSE, 12);
	gtk_box_pack_start (GTK_BOX (dialog_vbox), hbox, FALSE, FALSE, 0);
	gtk_container_set_border_width (GTK_CONTAINER (hbox), 5);
	gtk_widget_show (hbox);

	if (type == GTK_MESSAGE_ERROR) {
		image = gtk_image_new_from_stock ("gtk-dialog-error", GTK_ICON_SIZE_DIALOG);
	} else if (type == GTK_MESSAGE_QUESTION) {
		image = gtk_image_new_from_stock ("gtk-dialog-question", GTK_ICON_SIZE_DIALOG);
	} else if (type == GTK_MESSAGE_INFO) {
		image = gtk_image_new_from_stock ("gtk-dialog-info", GTK_ICON_SIZE_DIALOG);
	} else if (type == GTK_MESSAGE_WARNING) {
		image = gtk_image_new_from_stock ("gtk-dialog-warning", GTK_ICON_SIZE_DIALOG);
	} else {
		image = NULL;
		g_assert_not_reached ();
	}
	gtk_box_pack_start (GTK_BOX (hbox), image, FALSE, FALSE, 0);
	gtk_widget_show (image);

	vbox = gtk_vbox_new (FALSE, 6);
	gtk_box_pack_start (GTK_BOX (hbox), vbox, TRUE, TRUE, 0);
	gtk_widget_show (vbox);
	
	title = g_strconcat ("<b>", hdr, "</b>", NULL);
	label = gtk_label_new (title);  
	gtk_box_pack_start (GTK_BOX (vbox), label, FALSE, FALSE, 0);
	gtk_label_set_use_markup (GTK_LABEL (label), TRUE);
	gtk_label_set_justify (GTK_LABEL (label), GTK_JUSTIFY_LEFT);
	gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
	gtk_misc_set_alignment (GTK_MISC (label), 0, 0.5);
	gtk_widget_show (label);
	g_free (title);
	
	if ( ! ve_string_empty (msg)) {
		label = gtk_label_new (msg);
		gtk_box_pack_start (GTK_BOX (vbox), label, FALSE, FALSE, 0);
		if (markup)
			gtk_label_set_use_markup (GTK_LABEL (label), TRUE);
		gtk_label_set_justify (GTK_LABEL (label), GTK_JUSTIFY_LEFT);
		gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
		gtk_misc_set_alignment (GTK_MISC (label), 0, 0.5);
		gtk_widget_show (label);
	}
	
	dialog_action_area = GTK_DIALOG (dialog)->action_area;
	gtk_button_box_set_layout (GTK_BUTTON_BOX (dialog_action_area), GTK_BUTTONBOX_END);

	switch (buttons) 
  	{		
		case GTK_BUTTONS_NONE:
			break;

		case GTK_BUTTONS_OK:
		
			button = gtk_button_new_from_stock (GTK_STOCK_OK);
			gtk_dialog_add_action_widget (GTK_DIALOG (dialog), button, GTK_RESPONSE_OK);
			GTK_WIDGET_SET_FLAGS (button, GTK_CAN_DEFAULT);
			gtk_widget_show (button);

			gtk_dialog_set_default_response (GTK_DIALOG (dialog),
							 GTK_RESPONSE_OK);
			break;

		case GTK_BUTTONS_CLOSE:
		
			button = gtk_button_new_from_stock (GTK_STOCK_CLOSE);
			gtk_dialog_add_action_widget (GTK_DIALOG (dialog), button, GTK_RESPONSE_CLOSE);
			GTK_WIDGET_SET_FLAGS (button, GTK_CAN_DEFAULT);
			gtk_widget_show (button);

			gtk_dialog_set_default_response (GTK_DIALOG (dialog),
							 GTK_RESPONSE_CLOSE);
			break;

		case GTK_BUTTONS_CANCEL:
		
			button = gtk_button_new_from_stock (GTK_STOCK_CANCEL);
			gtk_dialog_add_action_widget (GTK_DIALOG (dialog), button, GTK_RESPONSE_CANCEL);
			GTK_WIDGET_SET_FLAGS (button, GTK_CAN_DEFAULT);
			gtk_widget_show (button);

			gtk_dialog_set_default_response (GTK_DIALOG (dialog),
							 GTK_RESPONSE_CLOSE);
			break;

		case GTK_BUTTONS_YES_NO:
		
			button = gtk_button_new_from_stock (GTK_STOCK_NO);
			gtk_dialog_add_action_widget (GTK_DIALOG (dialog), button, GTK_RESPONSE_NO);
			GTK_WIDGET_SET_FLAGS (button, GTK_CAN_DEFAULT);
			gtk_widget_show (button);

			button = gtk_button_new_from_stock (GTK_STOCK_YES);
			gtk_dialog_add_action_widget (GTK_DIALOG (dialog), button, GTK_RESPONSE_YES);
			GTK_WIDGET_SET_FLAGS (button, GTK_CAN_DEFAULT);
			gtk_widget_show (button);

			gtk_dialog_set_default_response (GTK_DIALOG (dialog),
							 GTK_RESPONSE_YES);
			break;
		
		
		case GTK_BUTTONS_OK_CANCEL:
	
			button = gtk_button_new_from_stock (GTK_STOCK_CANCEL);
  			gtk_widget_show (button);
  			gtk_dialog_add_action_widget (GTK_DIALOG (dialog), button, GTK_RESPONSE_CANCEL);
  			GTK_WIDGET_SET_FLAGS (button, GTK_CAN_DEFAULT);

		  	button = gtk_button_new_from_stock (GTK_STOCK_OK);
  			gtk_widget_show (button);
  			gtk_dialog_add_action_widget (GTK_DIALOG (dialog), button, GTK_RESPONSE_OK);
  			GTK_WIDGET_SET_FLAGS (button, GTK_CAN_DEFAULT);

			gtk_dialog_set_default_response (GTK_DIALOG (dialog),
							 GTK_RESPONSE_OK);
			break;

		default:
			g_assert_not_reached ();
			break;
  	}

	if (parent != NULL) {
		gtk_window_set_transient_for (GTK_WINDOW (dialog), GTK_WINDOW (parent));
	}
	if (flags & GTK_DIALOG_MODAL) {
		gtk_window_set_modal (GTK_WINDOW (dialog), TRUE);
	}
	if (flags & GTK_DIALOG_DESTROY_WITH_PARENT) {
		gtk_window_set_destroy_with_parent (GTK_WINDOW (dialog), TRUE);
	}

	g_free (msg);
	g_free (hdr);
	
  	return dialog;
}

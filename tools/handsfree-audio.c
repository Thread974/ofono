/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <gdbus.h>
#include <glib.h>

#define OFONO_SERVICE			"org.ofono"
#define HFP_AUDIO_MANAGER_PATH		"/"
#define HFP_AUDIO_MANAGER_INTERFACE	OFONO_SERVICE ".HandsfreeAudioManager"
#define HFP_AUDIO_AGENT_PATH		"/hfpaudioagent"
#define HFP_AUDIO_AGENT_INTERFACE	OFONO_SERVICE ".HandsfreeAudioAgent"

#define HFP_AUDIO_CVSD			1
#define HFP_AUDIO_MSBC			2

#define DBG(fmt, arg...) do {\
		g_print("%s: " fmt "\n", __FUNCTION__, ## arg);\
	} while (0)

/* DBus related */
static GMainLoop *main_loop = NULL;
static DBusConnection *conn;
static GSList *hcons = NULL;

static gboolean option_nocvsd = FALSE;
static gboolean option_nomsbc = FALSE;

struct hfp_audio_conn {
	unsigned char codec;
	int watch;
};

static void hfp_audio_conn_free(struct hfp_audio_conn *hcon)
{
	DBG("Freeing audio connection %p", hcon);

	hcons = g_slist_remove(hcons, hcon);
	g_source_remove(hcon->watch);
	g_free(hcon);
}

static gboolean hfp_audio_cb(GIOChannel *io, GIOCondition cond, gpointer data)
{
	struct hfp_audio_conn *hcon = data;
	gsize read;
	gsize written;
	char buf[60];

	if (cond & (G_IO_HUP | G_IO_NVAL | G_IO_ERR))
		goto fail;

	if (g_io_channel_read_chars(io, buf, sizeof(buf), &read, NULL) !=
			G_IO_STATUS_NORMAL)
		goto fail;

	g_io_channel_write_chars(io, buf+written, read, &written, NULL);

	return TRUE;

fail:
	DBG("Disconnected");
	hfp_audio_conn_free(hcon);
	return FALSE;
}

static DBusMessage *agent_newconnection(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	const char *card;
	int fd;
	unsigned char codec;
	GIOChannel *io;
	struct hfp_audio_conn *hcon;

	DBG("New connection");

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &card,
						DBUS_TYPE_UNIX_FD, &fd,
						DBUS_TYPE_BYTE, &codec,
						DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(msg,
				HFP_AUDIO_AGENT_INTERFACE ".InvalidArguments",
				"Invalid arguments");

	DBG("New connection: card=%s fd=%d codec=%d", card, fd, codec);

	io = g_io_channel_unix_new(fd);

	hcon = g_try_malloc0(sizeof(struct hfp_audio_conn));
	if (hcon == NULL)
		return NULL;

	hcon->codec = codec;
	hcon->watch = g_io_add_watch(io, G_IO_IN, hfp_audio_cb, hcon);
	hcons = g_slist_prepend(hcons, hcon);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *agent_release(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	DBG("HFP audio agent released");
	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable agent_methods[] = {
	{ GDBUS_METHOD("NewConnection", NULL, NULL, agent_newconnection) },
	{ GDBUS_METHOD("Release", NULL, NULL, agent_release) },
	{ },
};

static void hfp_audio_agent_register_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError err;

	dbus_error_init(&err);

	if (dbus_set_error_from_message(&err, reply) == TRUE) {
		DBG("Failed to register audio agent (%s: %s)", err.name,
								err.message);
		dbus_error_free(&err);
	} else {
		DBG("HFP audio agent registered");
	}

	dbus_message_unref(reply);
}

static void hfp_audio_agent_register(DBusConnection *conn)
{
	DBusMessage *msg;
	DBusPendingCall *call;
	const char *path = HFP_AUDIO_AGENT_PATH;
	unsigned char codecs[2];
	const unsigned char *pcodecs = codecs;
	int ncodecs = 0;

	DBG("Registering audio agent");

	msg = dbus_message_new_method_call(OFONO_SERVICE,
						HFP_AUDIO_MANAGER_PATH,
						HFP_AUDIO_MANAGER_INTERFACE,
						"Register");
	if (msg == NULL) {
		DBG("Not enough memory");
		return;
	}

	if (option_nocvsd == FALSE)
		codecs[ncodecs++] = HFP_AUDIO_CVSD;

	if (option_nomsbc == FALSE)
		codecs[ncodecs++] = HFP_AUDIO_MSBC;

	dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH, &path,
					DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
					&pcodecs, ncodecs, DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(conn, msg, &call, -1)) {
		dbus_message_unref(msg);
		DBG("Unable to register agent");
		return;
	}

	dbus_message_unref(msg);

	if (call == NULL) {
		DBG("Unable to register agent");
		return;
	}

	dbus_pending_call_set_notify(call, hfp_audio_agent_register_reply,
						NULL, NULL);

	dbus_pending_call_unref(call);
}

static void hfp_audio_agent_create(DBusConnection *conn)
{
	DBG("Creating audio agent");

	if (!g_dbus_register_interface(conn, HFP_AUDIO_AGENT_PATH,
					HFP_AUDIO_AGENT_INTERFACE,
					agent_methods, NULL, NULL,
					NULL, NULL)) {
		DBG("Unable to create local agent");
		g_main_loop_quit(main_loop);
	}
}

static void hfp_audio_agent_destroy(DBusConnection *conn)
{
	DBG("Destroying audio agent");

	g_dbus_unregister_interface(conn, HFP_AUDIO_AGENT_PATH,
						HFP_AUDIO_AGENT_INTERFACE);
}

static void ofono_connect(DBusConnection *conn, void *user_data)
{
	DBG("oFono appeared");

	hfp_audio_agent_register(conn);
}

static void ofono_disconnect(DBusConnection *conn, void *user_data)
{
	DBG("oFono disappeared");
}

static void disconnect_callback(DBusConnection *conn, void *user_data)
{
	DBG("Disconnected from BUS");

	g_main_loop_quit(main_loop);
}

static void sig_term(int sig)
{
	DBG("Terminating");

	g_main_loop_quit(main_loop);
}

static GOptionEntry options[] = {
	{ "nocvsd", 'c', 0, G_OPTION_ARG_NONE, &option_nocvsd,
				"Disable CVSD support" },
	{ "nomsbc", 'm', 0, G_OPTION_ARG_NONE, &option_nomsbc,
				"Disable MSBC support" },
	{ NULL },
};

int main(int argc, char **argv)
{
	GOptionContext *context;
	GError *error = NULL;
	DBusError err;
	guint watch;
	struct sigaction sa;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (g_option_context_parse(context, &argc, &argv, &error) == FALSE) {
		if (error != NULL) {
			DBG("%s", error->message);
			g_error_free(error);
		} else
			DBG("An unknown error occurred");
		exit(1);
	}

	g_option_context_free(context);

	if (option_nocvsd == TRUE && option_nomsbc == TRUE) {
		DBG("At least one codec must be supported");
		exit(2);
	}

	main_loop = g_main_loop_new(NULL, FALSE);

	dbus_error_init(&err);

	conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, &err);
	if (conn == NULL) {
		if (dbus_error_is_set(&err) == TRUE) {
			DBG("%s", err.message);
			dbus_error_free(&err);
		} else
			DBG("Can't register with system bus");
		exit(1);
	}

	g_dbus_set_disconnect_function(conn, disconnect_callback, NULL, NULL);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	hfp_audio_agent_create(conn);

	watch = g_dbus_add_service_watch(conn, OFONO_SERVICE,
				ofono_connect, ofono_disconnect, NULL, NULL);

	g_main_loop_run(main_loop);

	g_dbus_remove_watch(conn, watch);

	while (hcons != NULL)
		hfp_audio_conn_free(hcons->data);

	hfp_audio_agent_destroy(conn);

	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	return 0;
}

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
#include <sys/time.h>

#include <gdbus.h>
#include <glib.h>

#include <alsa/asoundlib.h>
#include <pthread.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/sco.h>

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
static GSList *threads = NULL;

static gboolean option_nocvsd = FALSE;
static gboolean option_nomsbc = FALSE;

enum {
	THREAD_STATE_DEFERED,
	THREAD_STATE_TRANSMIT
};

struct hfp_audio_thread {
	int state;
	unsigned char codec;
	int fd;
	int running;
	pthread_t thread;
};

static snd_pcm_t *hfp_audio_pcm_init(snd_pcm_stream_t stream)
{
	snd_pcm_t *pcm;
	DBG("Initializing pcm for %s", (stream == SND_PCM_STREAM_CAPTURE) ?
			"capture" : "playback");

	if (snd_pcm_open(&pcm, "default", stream, SND_PCM_NONBLOCK) < 0) {
		DBG("Failed to open pcm");
		return NULL;
	}

	/* 8000 khz, 16 bits, 128000 bytes/s, 48 bytes/frame, 6000 fps */
	if (snd_pcm_set_params(pcm, SND_PCM_FORMAT_S16_LE,
					SND_PCM_ACCESS_RW_INTERLEAVED,
					1, 8000, 1, 20000) < 0) {
		DBG("Failed to set pcm params");
		snd_pcm_close(pcm);
		pcm = NULL;
	}

	return pcm;
}

static void hfp_audio_thread_free(struct hfp_audio_thread *hcon)
{
	DBG("Freeing audio connection %p", hcon);
	if (!hcon)
		return;

	hcon->running = 0;
	if (hcon->thread)
		pthread_join(hcon->thread, NULL);

	threads = g_slist_remove(threads, hcon);
	g_free(hcon);
	DBG("freed %p", hcon);
}

/* Returns the number of data on sco socket */
static int hfp_audio_playback(int fd, snd_pcm_t *playback)
{
	char buf[800];
	snd_pcm_sframes_t frames;
	int total, captured, written, bytes;

	bytes = read(fd, buf, sizeof(buf));
	if (bytes < 0) {
		DBG("Failed to read: bytes %d, errno %d", bytes, errno);
		switch (errno) {
		case ENOTCONN:
			return -ENOTCONN;
		case EAGAIN:
			return 0;
		default:
			return -EINVAL;
		}
	}

	frames = snd_pcm_writei(playback, buf, bytes / 2);
	switch (frames) {
	case -EPIPE:
		DBG("Playback underrun");
		snd_pcm_prepare(playback);
		return bytes;
	case -EAGAIN:
		DBG("??? %d", bytes / 2);
		return bytes;
	case -EBADFD:
	case -ESTRPIPE:
		return -EINVAL;
	}

	if (frames < bytes / 2)
		DBG("played %d < requested %d", (int)frames, bytes / 2);

	return bytes;
}

/* Returns the number of data on sco socket */
static int hfp_audio_capture(int fd, snd_pcm_t *capture, GList **outq, int mtu)
{
	snd_pcm_sframes_t frames;
	int totalbytes, captured, written, bytes, tosend;
	gchar *buf;

	buf = g_try_malloc(mtu);
	if (!buf)
		return -ENOMEM;

	frames = snd_pcm_readi(capture, buf, mtu / 2);
	switch (frames) {
	case -EPIPE:
		DBG("Capture overrun");
		snd_pcm_prepare(capture);
		return 0;
	case -EAGAIN:
		DBG("No data to capture");
		return 0;
	case -EBADFD:
	case -ESTRPIPE:
		return -EINVAL;
	}

	*outq = g_list_append(*outq, buf);

	return frames * 2;
}

static void pop_outq(int fd, GList **outq, int qsize, int mtu)
{
	GList *el;

	el = g_list_first(*outq);
	if (!el)
		return;

	*outq = g_list_remove_link(*outq, el);
	write(fd, el->data, mtu);

	g_free(el->data);
	g_list_free(el);
}

static void *thread_func(void *userdata)
{
	struct hfp_audio_thread *hcon = userdata;
	snd_pcm_t *playback, *capture;
	int in, totalread = 0;
	int out, totalwrite = 0;
	int total, captured, written, bytes;
	GList *outq = NULL;
	struct timeval t0, t1, t;
	struct sco_options  opts;

	/* Add SCO options
	bytes = sizeof(opts);
	if (getsockopt(hcon->fd, SOL_SCO, SCO_OPTIONS, &opts, &bytes) < 0) {
		DBG("getsockopt failed");
		return NULL;
	}*/
	opts.mtu = 48;

	DBG("thread started mtu %d", opts.mtu);

	playback = hfp_audio_pcm_init(SND_PCM_STREAM_PLAYBACK);
	if (!playback)
		return NULL;

	capture = hfp_audio_pcm_init(SND_PCM_STREAM_CAPTURE);
	if (!capture) {
		snd_pcm_close(playback);
		return NULL;
	}

	gettimeofday(&t0, NULL);
	while (hcon->running) {
		in = hfp_audio_playback(hcon->fd, playback);
		if (hcon->state == THREAD_STATE_DEFERED)
			DBG("in %d", in);
		if ((in == 0 || in == -ENOTCONN) &&
				hcon->state == THREAD_STATE_DEFERED)
			goto schedule;
		else if (in < 0)
			break;
		else if (in > 0)
			hcon->state = THREAD_STATE_TRANSMIT;

		out = hfp_audio_capture(hcon->fd, capture, &outq, opts.mtu);
		if (out < 0)
			break;

		totalread += in;
		totalwrite += out;

		gettimeofday(&t1, NULL);
		pop_outq(hcon->fd, &outq, 20, opts.mtu);

		timersub(&t1, &t0, &t);
		/* More than one second passed? */
		if (t.tv_sec) {
			DBG("total: read %d, write %d", totalread, totalwrite);
			gettimeofday(&t0, NULL);
		}
schedule:
		usleep(2000);
	}

	DBG("thread terminating");
	snd_pcm_close(playback);
	snd_pcm_close(capture);
	return NULL;
}

static DBusMessage *agent_newconnection(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	const char *card;
	int fd, err;
	unsigned char codec;
	struct hfp_audio_thread *hcon;
	DBusMessage *reply;
	pthread_attr_t attr;

	DBG("New connection");

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &card,
						DBUS_TYPE_UNIX_FD, &fd,
						DBUS_TYPE_BYTE, &codec,
						DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(msg,
				HFP_AUDIO_AGENT_INTERFACE ".InvalidArguments",
				"Invalid arguments");

	DBG("New connection: card=%s fd=%d codec=%d", card, fd, codec);

	hcon = g_try_malloc0(sizeof(struct hfp_audio_thread));
	if (hcon == NULL)
		goto fail;

	hcon->state = THREAD_STATE_DEFERED;
	hcon->fd = fd;
	hcon->codec = codec;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		goto fail;

	hcon->running = 1;
	if (pthread_create(&hcon->thread, NULL, thread_func, hcon) < 0)
		goto fail;
	/* FIXME thread is not joined until we quit */

	threads = g_slist_prepend(threads, hcon);

	return reply;

fail:
	hfp_audio_thread_free(hcon);
	return g_dbus_create_error(msg,
			HFP_AUDIO_AGENT_INTERFACE ".Failed", "Failed to start");
}

static DBusMessage *agent_release(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	DBG("HFP audio agent released");
	/* agent will be registered on next oFono startup */
	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable agent_methods[] = {
	{ GDBUS_METHOD("NewConnection",
		GDBUS_ARGS({ "path", "o" }, { "fd", "h" }, { "codec", "y" }),
		NULL, agent_newconnection) },
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

	DBG("Registering audio agent in oFono");

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

	dbus_pending_call_set_notify(call, hfp_audio_agent_register_reply,
						NULL, NULL);

	dbus_pending_call_unref(call);
}

static void hfp_audio_agent_create(DBusConnection *conn)
{
	DBG("Registering audio agent on DBUS");

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
	DBG("Unregistering audio agent on DBUS");

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

	while (threads != NULL)
		hfp_audio_thread_free(threads->data);

	hfp_audio_agent_destroy(conn);

	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	return 0;
}

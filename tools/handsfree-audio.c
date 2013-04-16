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
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>

#include <gdbus.h>
#include <glib.h>
#include <pthread.h>

#include "bluetooth.h"
#include <alsa/asoundlib.h>

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
static gboolean option_server = FALSE;
static gboolean option_defer = FALSE;
static gchar *option_client_addr = NULL;

struct hfp_thread {
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

	/* 16 bits */
	if (snd_pcm_set_params(pcm, SND_PCM_FORMAT_S16_LE,
			SND_PCM_ACCESS_RW_INTERLEAVED, 1, 8000, 1, 120000) < 0) {
		DBG("Failed to set pcm params");
		snd_pcm_close(pcm);
		pcm = NULL;
	}

	return pcm;
}

static void hfp_audio_thread_free(struct hfp_thread *thread)
{
	DBG("Freeing audio connection %p", thread);

	if (!thread)
		return;

	thread->running = 0;
	if (thread->thread)
		pthread_join(thread->thread, NULL);

	if (shutdown(thread->fd, SHUT_RDWR) < 0)
			DBG("Failed to shutdown socket");
	if (close(thread->fd) < 0)
		DBG("Failed to close socket");

	threads = g_slist_remove(threads, thread);
	g_free(thread);
	DBG("freed %p", thread);
}

/* Returns the number of data on sco socket */
static int hfp_audio_playback(int fd, snd_pcm_t *playback)
{
	char buf[800];
	snd_pcm_sframes_t frames;
	int bytes;

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
		snd_pcm_prepare(playback);
		return bytes;
	case -EAGAIN:
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
	gchar *buf;

	buf = g_try_malloc(mtu);
	if (!buf)
		return -ENOMEM;

	frames = snd_pcm_readi(capture, buf, mtu / 2);
	switch (frames) {
	case -EPIPE:
		DBG("Capture overrun");
		snd_pcm_prepare(capture);
		g_free(buf);
		return 0;
	case -EAGAIN:
		DBG("No data to capture");
		g_free(buf);
		return 0;
	case -EBADFD:
	case -ESTRPIPE:
		DBG("Other error");
		g_free(buf);
		return -EINVAL;
	}

	if (frames < mtu / 2)
		DBG("Small frame: %d", (int) frames);

	if (g_list_length(*outq) > 32)
		DBG("Too many queued packets");

	*outq = g_list_append(*outq, buf);

	return frames * 2;
}

static void pop_outq(int fd, GList **outq, int mtu)
{
	GList *el;

	el = g_list_first(*outq);
	if (!el)
		return;

	*outq = g_list_remove_link(*outq, el);

	if (write(fd, el->data, mtu) < 0)
		DBG("Failed to write: %d", errno);

	g_free(el->data);
	g_list_free(el);
}

static void *thread_func(void *userdata)
{
	struct hfp_thread *thread = userdata;
	snd_pcm_t *playback, *capture;
	GList *outq = NULL;
	struct pollfd fds[8];
	int mtu = 48;

	DBG("thread started");

	capture = hfp_audio_pcm_init(SND_PCM_STREAM_CAPTURE);
	if (!capture)
		return NULL;

	playback = hfp_audio_pcm_init(SND_PCM_STREAM_PLAYBACK);
	if (!playback) {
		snd_pcm_close(capture);
		return NULL;
	}

	/* Force defered setup */
	if (recv(thread->fd, NULL, 0, 0) < 0)
		DBG("Defered setup failed: %d (%s)", errno, strerror(errno));

	while (thread->running) {
		/* Queue alsa captured data (snd_pcm_poll_descriptors failed) */
		if (hfp_audio_capture(thread->fd, capture, &outq, mtu) < 0) {
			DBG("Failed to capture");
			break;
		}

		memset(fds, 0, sizeof(fds));
		fds[0].fd = thread->fd;
		fds[0].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
		if (poll(fds, 1, 200) == 0)
			continue;

		if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
			DBG("POLLERR | POLLHUP | POLLNVAL triggered (%d)",
					fds[0].revents);
			break;
		}

		if (!fds[0].revents & POLLIN)
			continue;

		if (hfp_audio_playback(thread->fd, playback) < 0) {
			DBG("POLLIN triggered, but read error");
			break;
		}

		/* Dequeue in sync with readings */
		pop_outq(thread->fd, &outq, mtu);
	}

	DBG("thread terminating");
	snd_pcm_close(playback);
	snd_pcm_close(capture);
	return NULL;
}

static int new_connection(int fd, int codec)
{
	struct hfp_thread *thread;

	DBG("New connection: fd=%d codec=%d", fd, codec);
	thread = g_try_malloc0(sizeof(struct hfp_thread));
	if (thread == NULL)
		return -ENOMEM;

	thread->fd = fd;
	thread->running = 1;
	thread->codec = codec;

	if (pthread_create(&thread->thread, NULL, thread_func, thread) < 0) {
		hfp_audio_thread_free(thread);
		return -EINVAL;
	}

	/* FIXME thread is not detached until we quit */

	threads = g_slist_prepend(threads, thread);
	return 0;
}

static DBusMessage *agent_newconnection(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	const char *card;
	int fd;
	unsigned char codec;
	DBusMessage *reply;

	DBG("New connection");

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &card,
			DBUS_TYPE_UNIX_FD, &fd, DBUS_TYPE_BYTE, &codec,
			DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(msg,
				HFP_AUDIO_AGENT_INTERFACE ".InvalidArguments",
				"Invalid arguments");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		goto fail;

	if (new_connection(fd, codec) >= 0)
		return reply;

	dbus_message_unref(reply);

fail:
	close(fd);

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
		DBG("Failed to register audio agent (%s: %s)",
				err.name, err.message);
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
			HFP_AUDIO_MANAGER_PATH, HFP_AUDIO_MANAGER_INTERFACE,
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
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &pcodecs, ncodecs,
			DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(conn, msg, &call, -1)) {
		dbus_message_unref(msg);
		DBG("Unable to register agent");
		return;
	}

	dbus_message_unref(msg);

	dbus_pending_call_set_notify(call, hfp_audio_agent_register_reply, NULL,
			NULL);

	dbus_pending_call_unref(call);
}

static gboolean sco_accept_cb(GIOChannel *io, GIOCondition cond, gpointer data)
{
	struct sockaddr_sco addr;
	socklen_t optlen;
	int sk, nsk;

	if (cond & (G_IO_HUP | G_IO_NVAL | G_IO_ERR))
		goto fail;

	DBG("Incoming connection");
	sk = g_io_channel_unix_get_fd(io);
	nsk = accept(sk, (struct sockaddr *) &addr, &optlen);

	if (nsk > 0)
		new_connection(nsk, HFP_AUDIO_CVSD);

	return TRUE;

fail:
	DBG("Server disconnected");
	return FALSE;
}

static gboolean sco_connect_cb(GIOChannel *io, GIOCondition cond, gpointer data)
{
	int sk;

	if (cond & (G_IO_HUP | G_IO_NVAL | G_IO_ERR))
		goto fail;

	DBG("Connected");
	sk = g_io_channel_unix_get_fd(io);
	if (sk > 0)
		new_connection(sk, HFP_AUDIO_CVSD);

	return FALSE;

fail:
	DBG("Connection failed");
	return FALSE;
}

static int sco_listen_watch()
{
	struct sockaddr_sco saddr;
	int sk;
	GIOChannel *io;

	/* Create socket */
	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (sk < 0) {
		DBG("Can't create socket: %s (%d)", strerror(errno), errno);
		return -1;
	}

	/* Bind to local address */
	memset(&saddr, 0, sizeof(saddr));
	saddr.sco_family = AF_BLUETOOTH;

	if (bind(sk, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
		DBG("Can't bind socket: %s (%d)", strerror(errno), errno);
		goto fail;
	}

	/* Enable deferred setup */
	if (option_defer
			&& setsockopt(sk, SOL_BLUETOOTH, BT_DEFER_SETUP,
					&option_defer, sizeof(option_defer))
					< 0) {
		DBG("Can't defer setup : %s (%d)", strerror(errno), errno);
		goto fail;
	}

	/* Listen for connections */
	if (listen(sk, 10)) {
		DBG("Can not listen socket: %s (%d)", strerror(errno), errno);
		goto fail;
	}

	DBG("Waiting for connection ...");
	io = g_io_channel_unix_new(sk);
	if (!io)
		goto fail;

	return g_io_add_watch(io, G_IO_IN, sco_accept_cb, NULL);

fail:
	close(sk);
	return -1;
}

static int sco_connect_watch()
{
	struct sockaddr_sco saddr;
	int sk;
	GIOChannel *io;

	/* Create socket */
	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (sk < 0) {
		DBG("Can't create socket: %s (%d)", strerror(errno), errno);
		return -1;
	}

	/* Bind to local address */
	memset(&saddr, 0, sizeof(saddr));
	saddr.sco_family = AF_BLUETOOTH;

	if (bind(sk, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
		DBG("Can't bind socket: %s (%d)", strerror(errno), errno);
		goto fail;
	}

	/* Connect to remote address */
	memset(&saddr, 0, sizeof(saddr));
	saddr.sco_family = AF_BLUETOOTH;
	bt_str2ba(option_client_addr, &saddr.sco_bdaddr);
	if (connect(sk, (struct sockaddr *) &saddr, sizeof(saddr))) {
		DBG("Can not connect socket: %s (%d)", strerror(errno), errno);
		goto fail;
	}

	DBG("Connecting to %s...", option_client_addr);
	io = g_io_channel_unix_new(sk);
	if (!io)
		goto fail;

	return g_io_add_watch(io, G_IO_IN | G_IO_OUT, sco_connect_cb, NULL);

fail:
	close(sk);
	return -1;
}

static void hfp_audio_agent_create(DBusConnection *conn)
{
	DBG("Registering audio agent on DBUS");

	if (!g_dbus_register_interface(conn, HFP_AUDIO_AGENT_PATH,
			HFP_AUDIO_AGENT_INTERFACE, agent_methods, NULL, NULL,
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
	{ "defer", 'd', 0, G_OPTION_ARG_NONE, &option_defer,
				"Defered socket support" },
	{ "server", 'S', 0, G_OPTION_ARG_NONE, &option_server,
				"Server" },
	{ "client", 'C', 1, G_OPTION_ARG_STRING, &option_client_addr,
				"Client addr" },
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

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

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

	if (option_server) {
		watch = sco_listen_watch();
	} else if (option_client_addr != NULL) {
		watch = sco_connect_watch();
	} else {
		hfp_audio_agent_create(conn);
		watch = g_dbus_add_service_watch(conn, OFONO_SERVICE,
				ofono_connect, ofono_disconnect, NULL, NULL);
	}
	g_main_loop_run(main_loop);

	while (threads != NULL)
		hfp_audio_thread_free(threads->data);

	if (option_server) {
		g_source_remove(watch);
	} else if (option_client_addr != NULL) {
		g_source_remove(watch);
	} else {
		g_dbus_remove_watch(conn, watch);
		hfp_audio_agent_destroy(conn);
	}

	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	return 0;
}

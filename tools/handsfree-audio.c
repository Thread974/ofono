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
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>

#include <gdbus.h>
#include <glib.h>

#include <alsa/asoundlib.h>
#include <sbc/sbc.h>
#include "bluetooth.h"

#define OFONO_SERVICE			"org.ofono"
#define HFP_AUDIO_MANAGER_PATH		"/"
#define HFP_AUDIO_MANAGER_INTERFACE	OFONO_SERVICE ".HandsfreeAudioManager"
#define HFP_AUDIO_AGENT_PATH		"/hfpaudioagent"
#define HFP_AUDIO_AGENT_INTERFACE	OFONO_SERVICE ".HandsfreeAudioAgent"
#define HFP_AUDIO_CARD_INTERFACE	OFONO_SERVICE ".HandsfreeAudioCard"

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

static const char sntable[4] = { 0x08, 0x38, 0xC8, 0xF8 };
static const int audio_rates[3] = { 0, 8000, 16000 };

char *card_path;

struct msbc_parser {
	uint8_t buffer[60];
	int parsed;
};

struct msbc_codec {
	sbc_t sbcenc; /* Coder data */
	char *ebuffer; /* Codec transfer buffer */
	size_t ebuffer_size; /* Size of the buffer */
	size_t ebuffer_start; /* start of encoding data */
	size_t ebuffer_end; /* end of encoding data */

	struct msbc_parser parser; /* mSBC parser for concatenating frames */
	sbc_t sbcdec; /* Decoder data */

	size_t msbc_frame_size;
	size_t decoded_frame_size;
};

struct hfp_thread {
	int fd;
	int running;
	pthread_t thread;
	GSList *outq;

	int rate;
	char *capture_buffer;
	int capture_size;
	int captured;
	int mtu;
	int (*init)(struct hfp_thread *);
	int (*free)(struct hfp_thread *);
	int (*encode)(struct hfp_thread *, char *data, int len);
	int (*decode)(struct hfp_thread *, char *data, int len, char *out,
								int outlen);
	struct msbc_codec msbc;
};

static void msbc_parser_reset(struct msbc_parser *p)
{
	p->parsed = 0;
}

static int msbc_state_machine(struct msbc_parser *p, uint8_t byte)
{
	switch (p->parsed) {
	case 0:
		if (byte == 0x01)
			goto copy;
		return 0;
	case 1:
		if (byte == 0x08 || byte == 0x38 || byte == 0xC8
				|| byte == 0xF8)
			goto copy;
		break;
	case 2:
		if (byte == 0xAD)
			goto copy;
		break;
	case 3:
		if (byte == 0x00)
			goto copy;
		break;
	case 4:
		if (byte == 0x00)
			goto copy;
		break;
	default:
		goto copy;
	}

	msbc_parser_reset(p);
	return 0;

copy:
	p->buffer[p->parsed] = byte;
	p->parsed++;

	return p->parsed;
}

static size_t msbc_parse(sbc_t *sbcdec, struct msbc_parser *p, char *data,
		int len, char *out, int outlen, int *bytes)
{
	size_t totalwritten = 0;
	size_t written = 0;
	int i;
	*bytes = 0;

	for (i = 0; i < len; i++) {
		if (msbc_state_machine(p, data[i]) == 60) {
			int decoded;
			decoded = sbc_decode(sbcdec, p->buffer + 2,
					p->parsed - 2 - 1, out, outlen, &written);
			if (decoded > 0) {
				totalwritten += written;
				*bytes += decoded;
			} else {
				DBG("Error while decoding: %d", decoded);
			}
			msbc_parser_reset(p);
		}
	}

	return totalwritten;
}

static int hfp_audio_cvsd_init(struct hfp_thread *thread)
{
	thread->rate = 8000;
	thread->capture_size = 48;

	return 0;
}

static int hfp_audio_cvsd_free(struct hfp_thread *thread)
{
	return 0;
}

static int hfp_audio_cvsd_encode(struct hfp_thread *thread, char *data,
						int len)
{
	char *qbuf;

	if (len > thread->mtu) {
		DBG("Mtu too small: len %d, mtu %d", len, thread->mtu);
		return -EINVAL;
	}

	qbuf = g_try_malloc(thread->mtu);
	if (!qbuf)
		return -ENOMEM;

	memcpy(qbuf, data, len);

	thread->outq = g_slist_insert(thread->outq, qbuf, -1);

	return len;
}

static int hfp_audio_cvsd_decode(struct hfp_thread *thread, char *data,
						int len, char *out, int outlen)
{
	int size = (len < outlen) ? len : outlen;

	memcpy(out, data, size);

	return size;
}

/* Run from IO thread */
static int hfp_audio_msbc_init(struct hfp_thread *thread)
{
	struct msbc_codec *codec = &thread->msbc;
	struct bt_voice voice;

	thread->rate = 16000;
	thread->capture_size = 240; /* decoded mSBC frame */

	memset(&voice, 0, sizeof(voice));
	voice.setting = BT_VOICE_TRANSPARENT;
	if (setsockopt(thread->fd, SOL_BLUETOOTH, BT_VOICE, &voice, sizeof(voice))
			< 0) {
		DBG("Can't set transparent mode: %s (%d)",
				strerror(errno), errno);
		return -EOPNOTSUPP;
	}

	sbc_init_msbc(&codec->sbcenc, 0);
	sbc_init_msbc(&codec->sbcdec, 0);

	codec->msbc_frame_size = 2 + sbc_get_frame_length(&codec->sbcenc) + 1;
	codec->decoded_frame_size = sbc_get_codesize(&codec->sbcenc);
	msbc_parser_reset(&codec->parser);

	/* 5 * 48 == 10 * 24 == 4 * 60 */
	codec->ebuffer_size = codec->msbc_frame_size * 4;
	codec->ebuffer = g_try_malloc(codec->ebuffer_size);
	codec->ebuffer_start = 0;
	codec->ebuffer_end = 0;

	DBG("codec->msbc_frame_size %d", (int) codec->msbc_frame_size);
	DBG("codec->ebuffer_size %d", (int) codec->ebuffer_size);
	DBG("codec->decoded_frame_size %d", (int) codec->decoded_frame_size);

	return 0;
}

/* Run from IO thread */
static int hfp_audio_msbc_free(struct hfp_thread *thread)
{
	struct msbc_codec *codec = &thread->msbc;

	g_free(codec->ebuffer);
	sbc_finish(&codec->sbcenc);
	sbc_finish(&codec->sbcdec);

	return 0;
}

/* Run from IO thread */
static int hfp_audio_msbc_encode(struct hfp_thread *thread, char *data, int len)
{
	struct msbc_codec *codec = &thread->msbc;
	char *h2 = codec->ebuffer + codec->ebuffer_end;
	static int sn = 0;
	int written = 0;
	char *qbuf;

	h2[0] = 0x01;
	h2[1] = sntable[sn];
	h2[59] = 0xff;
	sn = (sn + 1) % 4;

	sbc_encode(&codec->sbcenc, data, len,
			codec->ebuffer + codec->ebuffer_end + 2,
			codec->ebuffer_size - codec->ebuffer_end - 2,
			(ssize_t *) &written);

	written += 2 /* H2 */ + 1 /* 0xff */;
	codec->ebuffer_end += written;

	/* Split into MTU sized chunks */
	while (codec->ebuffer_start + thread->mtu <= codec->ebuffer_end) {
		qbuf = g_try_malloc(thread->mtu);
		if (!qbuf)
			return -ENOMEM;

		memcpy(qbuf, codec->ebuffer + codec->ebuffer_start, thread->mtu);

		thread->outq = g_slist_insert(thread->outq, qbuf, -1);

		codec->ebuffer_start += thread->mtu;
		if (codec->ebuffer_start >= codec->ebuffer_end)
			codec->ebuffer_start = codec->ebuffer_end = 0;
	}

	return 0;
}

/* Run from IO thread */
static int hfp_audio_msbc_decode(struct hfp_thread *thread, char *data,
						int len, char *out, int outlen)
{
	struct msbc_codec *codec = &thread->msbc;
	int written, decoded;

	written = msbc_parse(&codec->sbcdec, &codec->parser, data, len, out,
			outlen, &decoded);

	return written;
}

static snd_pcm_t *hfp_audio_pcm_init(snd_pcm_stream_t stream, int rate)
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
			SND_PCM_ACCESS_RW_INTERLEAVED, 1, rate, 1, 120000) < 0) {
		DBG("Failed to set pcm params");
		snd_pcm_close(pcm);
		return NULL;
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
static int hfp_audio_playback(struct hfp_thread *thread,
		snd_pcm_t *playback)
{
	char buf[512], out[512];
	int bytes, outlen;
	snd_pcm_sframes_t frames;

	bytes = read(thread->fd, buf, sizeof(buf));
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

	outlen = thread->decode(thread, buf, bytes, out, sizeof(out));

	frames = snd_pcm_writei(playback, out, outlen / 2);
	switch (frames) {
	case -EPIPE:
		snd_pcm_prepare(playback);
		return bytes;
	case -EAGAIN:
		/* Do as if it was written */
		return bytes;
	case -EBADFD:
	case -ESTRPIPE:
		return -EINVAL;
	}

	if (frames < outlen / 2)
		DBG("played %d < requested %d", (int)frames, outlen / 2);

	return bytes;
}

/* Returns the number of data on sco socket */
static int hfp_audio_capture(struct hfp_thread *thread, snd_pcm_t *capture)
{
	snd_pcm_sframes_t frames;

	frames = snd_pcm_readi(capture, thread->capture_buffer+thread->captured,
				(thread->capture_size - thread->captured) / 2);
	switch (frames) {
	case -EPIPE:
		snd_pcm_prepare(capture);
		return 0;
	case -EAGAIN:
		return 0;
	case -EBADFD:
	case -ESTRPIPE:
		DBG("Other error %s (%d)", strerror(frames), (int) frames);
		return -EINVAL;
	}

	thread->captured += frames * 2;
	if (thread->captured < thread->capture_size)
		return frames * 2;

	thread->encode(thread, thread->capture_buffer, thread->captured);
	thread->captured = 0;

	return frames * 2;
}

static void pop_outq(struct hfp_thread *thread)
{
	char *qbuf;

	while (thread->outq != NULL) {
		qbuf = thread->outq->data;
		thread->outq = g_slist_remove(thread->outq, qbuf);

		if (write(thread->fd, qbuf, thread->mtu) < 0)
			DBG("Failed to write: %d", errno);

		g_free(qbuf);
	}
}

static void *thread_func(void *userdata)
{
	struct hfp_thread *thread = userdata;
	snd_pcm_t *playback, *capture;
	struct pollfd fds[8];

	DBG("thread started: rate %d", thread->rate);

	if (thread->init(thread) < 0)
		return NULL;

	capture = hfp_audio_pcm_init(SND_PCM_STREAM_CAPTURE, thread->rate);
	if (!capture)
		return NULL;

	playback = hfp_audio_pcm_init(SND_PCM_STREAM_PLAYBACK, thread->rate);
	if (!playback) {
		snd_pcm_close(capture);
		return NULL;
	}

	thread->capture_buffer = g_try_malloc(thread->capture_size);
	if (!thread->capture_buffer) {
		snd_pcm_close(capture);
		snd_pcm_close(playback);
		return NULL;
	}

	/* Force defered setup */
	if (recv(thread->fd, NULL, 0, 0) < 0)
		DBG("Defered setup failed: %d (%s)", errno, strerror(errno));

	thread->mtu = 48;
	DBG("thread->mtu %d", thread->mtu);

	while (thread->running) {
		/* Queue alsa captured data (snd_pcm_poll_descriptors failed) */
		if (hfp_audio_capture(thread, capture) < 0) {
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

		if (hfp_audio_playback(thread, playback) < 0) {
			DBG("POLLIN triggered, but read error");
			break;
		}

		/* Dequeue in sync with readings */
		pop_outq(thread);
	}

	DBG("thread terminating");
	g_slist_free_full(thread->outq, g_free);
	g_free(thread->capture_buffer);
	snd_pcm_close(playback);
	snd_pcm_close(capture);

	thread->free(thread);

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

	switch (codec) {
	case HFP_AUDIO_CVSD:
		thread->init = hfp_audio_cvsd_init;
		thread->free = hfp_audio_cvsd_free;
		thread->decode = hfp_audio_cvsd_decode;
		thread->encode = hfp_audio_cvsd_encode;
		break;
	case HFP_AUDIO_MSBC:
		thread->rate = 16000;
		thread->init = hfp_audio_msbc_init;
		thread->free = hfp_audio_msbc_free;
		thread->decode = hfp_audio_msbc_decode;
		thread->encode = hfp_audio_msbc_encode;
		break;
	default:
		return -EINVAL;
	}

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
	} else
		DBG("HFP audio agent registered");

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

static void sig_user(int sig)
{
	DBusMessage *msg;

	if (sig == SIGUSR1) {
		if (!card_path) {
			DBG("No audio card");
			return;
		}

		DBG("Request audio connection");

		msg = dbus_message_new_method_call(OFONO_SERVICE, card_path,
					HFP_AUDIO_CARD_INTERFACE, "Connect");
		if (msg == NULL) {
			DBG("Not enough memory");
			return;
		}

		g_dbus_send_message(conn, msg);
	}
}

static gboolean card_added(DBusConnection *connection, DBusMessage *message,
			void *user_data)
{
	DBusMessageIter iter;
	const char *path;

	dbus_message_iter_init(message, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH)
		return FALSE;

	dbus_message_iter_get_basic(&iter, &path);
	DBG("%s", path);

	card_path = g_strdup(path);

	return TRUE;
}

static gboolean card_removed(DBusConnection *connection, DBusMessage *message,
			void *user_data)
{
	DBusMessageIter iter;
	const char *path;

	dbus_message_iter_init(message, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH)
		return FALSE;

	dbus_message_iter_get_basic(&iter, &path);
	DBG("%s", path);

	g_free(card_path);
	card_path = NULL;

	return TRUE;
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
	guint add_card_watch = 0;
	guint remove_card_watch = 0;
	struct sigaction sa;
	struct sigaction sa_user;

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

	memset(&sa_user, 0, sizeof(sa_user));
	sa_user.sa_handler = sig_user;
	sigaction(SIGUSR1, &sa_user, NULL);

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

	hfp_audio_agent_create(conn);

	watch = g_dbus_add_service_watch(conn, OFONO_SERVICE,
				ofono_connect, ofono_disconnect, NULL, NULL);

	add_card_watch = g_dbus_add_signal_watch(conn, OFONO_SERVICE,
						HFP_AUDIO_MANAGER_PATH,
						HFP_AUDIO_MANAGER_INTERFACE,
						"CardAdded", card_added,
						NULL, NULL);
	remove_card_watch = g_dbus_add_signal_watch(conn, OFONO_SERVICE,
						HFP_AUDIO_MANAGER_PATH,
						HFP_AUDIO_MANAGER_INTERFACE,
						"CardRemoved", card_removed,
						NULL, NULL);

	g_main_loop_run(main_loop);

	while (threads != NULL)
		hfp_audio_thread_free(threads->data);

	g_dbus_remove_watch(conn, watch);
	g_dbus_remove_watch(conn, add_card_watch);
	g_dbus_remove_watch(conn, remove_card_watch);
	hfp_audio_agent_destroy(conn);

	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	return 0;
}

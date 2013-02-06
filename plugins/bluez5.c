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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <string.h>

#include <glib.h>

#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/dbus.h>
#include <ofono/plugin.h>
#include <ofono/log.h>

#include <gdbus/gdbus.h>
#include "bluez5.h"

#define BLUEZ_PROFILE_MGMT_INTERFACE   BLUEZ_SERVICE ".ProfileManager1"

struct bt_endpoint {
	char *owner;
	char *path;
	uint8_t codec;
};

void bt_endpoint_free(struct bt_endpoint *endpoint)
{
	g_free(endpoint->owner);
	g_free(endpoint->path);
	g_free(endpoint);
}

static struct bt_endpoint *endpoint_new(const char *owner, const char *path,
								uint8_t codec)
{
	struct bt_endpoint *endpoint;

	endpoint = g_new0(struct bt_endpoint, 1);
	endpoint->owner = g_strdup(owner);
	endpoint->path = g_strdup(path);
	endpoint->codec = codec;

	return endpoint;
}

static guint sco_watch;
static GSList *sco_cbs;

static void parse_uint16(DBusMessageIter *iter, gpointer user_data)
{
	uint16_t *value = user_data;

	if (dbus_message_iter_get_arg_type(iter) !=  DBUS_TYPE_UINT16)
		return;

	dbus_message_iter_get_basic(iter, value);
}

static void parse_string(DBusMessageIter *iter, gpointer user_data)
{
	char **str = user_data;
	int arg_type = dbus_message_iter_get_arg_type(iter);

	if (arg_type != DBUS_TYPE_OBJECT_PATH && arg_type != DBUS_TYPE_STRING)
		return;

	dbus_message_iter_get_basic(iter, str);
}

static void parse_byte(DBusMessageIter *iter, gpointer user_data)
{
	guint8 *value = user_data;

	if (dbus_message_iter_get_arg_type(iter) !=  DBUS_TYPE_BYTE)
		return;

	dbus_message_iter_get_basic(iter, value);
}

static void parse_endpoints(DBusMessageIter *array, gpointer user_data)
{
	GSList **endpoints = user_data;
	struct bt_endpoint *endpoint;
	const char *path, *owner;
	guint8 codec;
	DBusMessageIter dict, variant, entry;

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		path = NULL;
		codec = 0x00;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return;

		dbus_message_iter_get_basic(&entry, &owner);

		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			return;

		dbus_message_iter_recurse(&entry, &variant);

		ofono_dbus_iter_parse_properties(&variant,
				"Path", parse_string, &path,
				"Codec", parse_byte, &codec,
				NULL);

		dbus_message_iter_next(&dict);

		endpoint = endpoint_new(owner, path, codec);
		*endpoints = g_slist_append(*endpoints, endpoint);

		DBG("Media Endpoint %s %s codec: 0x%02X", owner, path, codec);
	}
}

int bt_parse_fd_properties(DBusMessageIter *iter, uint16_t *version,
				uint16_t *features, GSList **endpoints)
{
	uint16_t ver = 0, feat = 0;

	if (endpoints)
		ofono_dbus_iter_parse_properties(iter,
				"Version", parse_uint16, &ver,
				"Features", parse_uint16, &feat,
				"MediaEndpoints", parse_endpoints, endpoints,
				NULL);
	else
		ofono_dbus_iter_parse_properties(iter,
				"Version", parse_uint16, &ver,
				"Features", parse_uint16, &feat,
				NULL);

	if (version)
		*version = ver;

	if (features)
		*features = feat;

	return 0;
}

void bt_bacpy(bdaddr_t *dst, const bdaddr_t *src)
{
	memcpy(dst, src, sizeof(bdaddr_t));
}

int bt_ba2str(const bdaddr_t *ba, char *str)
{
	return sprintf(str, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
		ba->b[5], ba->b[4], ba->b[3], ba->b[2], ba->b[1], ba->b[0]);
}

int bt_bacmp(const bdaddr_t *ba1, const bdaddr_t *ba2)
{
	return memcmp(ba1, ba2, sizeof(bdaddr_t));
}

static gboolean sco_accept(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct sockaddr_sco saddr;
	socklen_t alen;
	int sk, nsk;
	GSList *l;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		return FALSE;

	sk = g_io_channel_unix_get_fd(io);

	memset(&saddr, 0, sizeof(saddr));
	alen = sizeof(saddr);

	nsk = accept(sk, (struct sockaddr *) &saddr, &alen);
	if (nsk < 0)
		return TRUE;

	for (l = sco_cbs; l; l = l->next) {
		bt_sco_accept_cb cb = l->data;

		if (cb(nsk, &saddr))
			return TRUE;
	}

	ofono_warn("No SCO callback for incoming connection");
	close(nsk);

	return TRUE;
}

static int sco_init(void)
{
	GIOChannel *sco_io;
	struct sockaddr_sco saddr;
	int sk, defer_setup = 1;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET | O_NONBLOCK | SOCK_CLOEXEC,
								BTPROTO_SCO);
	if (sk < 0)
		return -errno;

	/* Bind to local address */
	memset(&saddr, 0, sizeof(saddr));
	saddr.sco_family = AF_BLUETOOTH;
	bt_bacpy(&saddr.sco_bdaddr, BDADDR_ANY);

	if (bind(sk, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
		close(sk);
		return -errno;
	}

	if (setsockopt(sk, SOL_BLUETOOTH, BT_DEFER_SETUP,
				&defer_setup, sizeof(defer_setup)) < 0)
		ofono_warn("Can't enable deferred setup: %s (%d)",
						strerror(errno), errno);

	if (listen(sk, 5) < 0) {
		close(sk);
		return -errno;
	}

	sco_io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(sco_io, TRUE);

	sco_watch = g_io_add_watch(sco_io,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				sco_accept, NULL);

	g_io_channel_unref(sco_io);

	return 0;
}

int bt_register_sco_server(bt_sco_accept_cb cb)
{
	int err;

	if (!cb) {
		ofono_error("SCO: invalid callback");
		return -1;
	}

	if (!sco_cbs) {
		err = sco_init();
		if (err < 0) {
			ofono_error("SCO: %s(%d)", strerror(-err), -err);
			return err;
		}
	}

	sco_cbs = g_slist_append(sco_cbs, cb);

	return 0;
}

void bt_unregister_sco_server(bt_sco_accept_cb cb)
{
	if (!cb) {
		ofono_error("SCO: invalid callback");
		return;
	}

	sco_cbs = g_slist_remove(sco_cbs, cb);
	if (sco_cbs)
		return;

	g_source_remove(sco_watch);
}

static void profile_register_cb(DBusPendingCall *call, gpointer user_data)
{
	DBusMessage *reply;
	DBusError derr;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);

	if (dbus_set_error_from_message(&derr, reply)) {
		ofono_error("RegisterProfile() replied an error: %s, %s",
						derr.name, derr.message);
		dbus_error_free(&derr);
		goto done;
	}

	DBG("");

done:
	dbus_message_unref(reply);
}

static void unregister_profile_cb(DBusPendingCall *call, gpointer user_data)
{
	DBusMessage *reply;
	DBusError derr;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);

	if (dbus_set_error_from_message(&derr, reply)) {
		ofono_error("UnregisterProfile() replied an error: %s, %s",
						derr.name, derr.message);
		dbus_error_free(&derr);
		goto done;
	}

	DBG("");

done:
	dbus_message_unref(reply);
}

int bluetooth_register_profile(DBusConnection *conn, const char *uuid,
					const char *name, const char *object)
{
	DBusMessageIter iter, dict;
	DBusPendingCall *c;
	DBusMessage *msg;

	DBG("Bluetooth: Registering %s (%s) profile", uuid, name);

	msg = dbus_message_new_method_call(BLUEZ_SERVICE, "/org/bluez",
			BLUEZ_PROFILE_MGMT_INTERFACE, "RegisterProfile");

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &object);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &uuid);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dict);
	ofono_dbus_dict_append(&dict, "Name", DBUS_TYPE_STRING, &name);

	dbus_message_iter_close_container(&iter, &dict);

	if (!dbus_connection_send_with_reply(conn, msg, &c, -1)) {
		ofono_error("Sending RegisterProfile failed");
		dbus_message_unref(msg);
		return -EIO;
	}

	dbus_pending_call_set_notify(c, profile_register_cb, NULL, NULL);
	dbus_pending_call_unref(c);

	dbus_message_unref(msg);

	return 0;
}

void bluetooth_unregister_profile(DBusConnection *conn, const char *object)
{
	DBusMessageIter iter;
	DBusPendingCall *c;
	DBusMessage *msg;

	DBG("Bluetooth: Unregistering profile %s", object);

	msg = dbus_message_new_method_call(BLUEZ_SERVICE, "/org/bluez",
			BLUEZ_PROFILE_MGMT_INTERFACE, "UnregisterProfile");

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &object);

	if (!dbus_connection_send_with_reply(conn, msg, &c, -1)) {
		ofono_error("Sending UnregisterProfile failed");
		dbus_message_unref(msg);
		return;
	}

	dbus_pending_call_set_notify(c, unregister_profile_cb, NULL, NULL);
	dbus_pending_call_unref(c);

	dbus_message_unref(msg);
}

OFONO_PLUGIN_DEFINE(bluez5, "BlueZ 5 Utils Plugin", VERSION,
			OFONO_PLUGIN_PRIORITY_DEFAULT, NULL, NULL)

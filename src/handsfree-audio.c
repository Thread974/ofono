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
#include <stdio.h>
#include <string.h>

#include <gdbus.h>

#include <ofono/handsfree-audio.h>

#include "ofono.h"

#define HFP_AUDIO_MANAGER_INTERFACE	OFONO_SERVICE ".HandsfreeAudioManager"
#define HFP_AUDIO_AGENT_INTERFACE	OFONO_SERVICE ".HandsfreeAudioAgent"
#define HFP_AUDIO_CARD_INTERFACE	OFONO_SERVICE ".HandsfreeAudioCard"

/* Supported agent codecs */
enum hfp_codec {
	HFP_CODEC_CVSD = 0x01,
	HFP_CODEC_MSBC = 0x02,
};

struct agent {
	char *owner;
	char *path;
	unsigned char *codecs;
	int codecs_len;
	guint watch;
};

static GSList *cards = NULL;
static struct agent *agent = NULL;
static unsigned int modemwatch_id;
static int ref_count = 0;

static void agent_free(struct agent *agent)
{
	if (agent->watch > 0)
		g_dbus_remove_watch(ofono_dbus_get_connection(), agent->watch);

	g_free(agent->owner);
	g_free(agent->path);
	g_free(agent->codecs);
	g_free(agent);
}

static void agent_release(struct agent *agent)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(agent->owner, agent->path,
					HFP_AUDIO_AGENT_INTERFACE, "Release");

	g_dbus_send_message(ofono_dbus_get_connection(), msg);
}

static void agent_disconnect(DBusConnection *conn, void *user_data)
{
	DBG("Agent %s disconnected", agent->owner);

	agent_free(agent);
	agent = NULL;
}

static void card_append_properties(DBusMessageIter *iter,
						struct ofono_modem *modem)
{
	DBusMessageIter dict;
	const char *address;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					OFONO_PROPERTIES_ARRAY_SIGNATURE,
					&dict);

	address = ofono_modem_get_string(modem, "Remote");

	ofono_dbus_dict_append(&dict, "RemoteAddress",
					DBUS_TYPE_STRING, &address);

	dbus_message_iter_close_container(iter, &dict);
}

static DBusMessage *am_get_cards(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	return __ofono_error_not_implemented(msg);
}

static DBusMessage *am_agent_register(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	const char *sender, *path;
	unsigned char *codecs;
	DBusMessageIter iter, array;
	int length, i;

	if (agent)
		return __ofono_error_in_use(msg);

	sender = dbus_message_get_sender(msg);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &path);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &array);
	dbus_message_iter_get_fixed_array(&array, &codecs, &length);

	if (length == 0)
		return __ofono_error_invalid_args(msg);

	for (i = 0; i < length; i++) {
		if (codecs[i] != HFP_CODEC_CVSD &&
				codecs[i] != HFP_CODEC_MSBC)
			return __ofono_error_invalid_args(msg);
	}

	agent = g_new0(struct agent, 1);
	agent->owner = g_strdup(sender);
	agent->path = g_strdup(path);
	agent->codecs = g_memdup(codecs, length);
	agent->codecs_len = length;
	agent->watch = g_dbus_add_disconnect_watch(conn, sender,
						agent_disconnect, NULL, NULL);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *am_agent_unregister(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	const char *sender, *path;
	DBusMessageIter iter;

	if (agent == NULL)
		return __ofono_error_not_found(msg);

	sender = dbus_message_get_sender(msg);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __ofono_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &path);

	if (strcmp(sender, agent->owner) != 0)
		return __ofono_error_not_allowed(msg);

	if (strcmp(path, agent->path) != 0)
		return __ofono_error_not_found(msg);

	agent_free(agent);
	agent = NULL;

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable am_methods[] = {
	{ GDBUS_METHOD("GetCards",
			NULL, GDBUS_ARGS({"cards", "a{oa{sv}}"}),
			am_get_cards) } ,
	{ GDBUS_METHOD("Register",
			GDBUS_ARGS({"path", "o"}, {"codecs", "ay"}), NULL,
			am_agent_register) },
	{ GDBUS_METHOD("Unregister",
			GDBUS_ARGS({"path", "o"}), NULL,
			am_agent_unregister) },
	{ }
};

static const GDBusSignalTable am_signals[] = {
	{ GDBUS_SIGNAL("CardAdded",
		GDBUS_ARGS({ "path", "o" }, { "properties", "a{sv}" })) },
	{ GDBUS_SIGNAL("CardRemoved",
		GDBUS_ARGS({ "path", "o" })) },
	{ }
};

static DBusMessage *card_get_properties(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct ofono_modem *modem = user_data;
	DBusMessage *reply;
	DBusMessageIter iter;

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	card_append_properties(&iter, modem);

	return reply;
}

static const GDBusMethodTable card_methods[] = {
	{ GDBUS_METHOD("GetProperties",
				NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
				card_get_properties) },
	{ }
};

static void am_emit_card_added(const char *path, struct ofono_modem *modem)
{
	DBusMessage *signal;
	DBusMessageIter iter;

	signal = dbus_message_new_signal("/", HFP_AUDIO_MANAGER_INTERFACE,
								"CardAdded");
	if (signal == NULL) {
		ofono_error("Unable to allocate new CardAdded signal");
		return;
	}

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &path);

	card_append_properties(&iter, modem);

	g_dbus_send_message(ofono_dbus_get_connection(), signal);
}

static void am_emit_card_removed(const char *path, struct ofono_modem *modem)
{
	DBusMessage *signal;
	DBusMessageIter iter;

	signal = dbus_message_new_signal("/", HFP_AUDIO_MANAGER_INTERFACE,
								"CardRemoved");
	if (signal == NULL) {
		ofono_error("Unable to allocate new CardRemoved signal");
		return;
	}

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &path);

	g_dbus_send_message(ofono_dbus_get_connection(), signal);
}

static void am_card_add(const char *path, struct ofono_modem *modem)
{
	if (!g_dbus_register_interface(ofono_dbus_get_connection(), path,
					HFP_AUDIO_CARD_INTERFACE, card_methods,
					NULL, NULL, modem, NULL))
		return;

	am_emit_card_added(path, modem);

	DBG("Audio Card added: %s", path);
}

static void am_card_remove(const char *path, struct ofono_modem *modem)
{
	am_emit_card_removed(path, modem);

	g_dbus_unregister_interface(ofono_dbus_get_connection(), path,
						HFP_AUDIO_CARD_INTERFACE);

	DBG("Audio Card removed: %s", path);
}

static void handsfree_modem_watch(struct ofono_atom *atom,
			enum ofono_atom_watch_condition cond, void *user_data)
{
	struct ofono_modem *modem = user_data;
	const char *path = __ofono_atom_get_path(atom);

	if (cond == OFONO_ATOM_WATCH_CONDITION_REGISTERED) {
		am_card_add(path, modem);
		cards = g_slist_append(cards, atom);
	} else {
		am_card_remove(path, modem);
		cards = g_slist_remove(cards, atom);
	}
}

static void modem_watch(struct ofono_modem *modem, gboolean added, void *user)
{
	if (added == FALSE)
		return;

	__ofono_modem_add_atom_watch(modem, OFONO_ATOM_TYPE_HANDSFREE,
					handsfree_modem_watch, modem, NULL);
}

void ofono_handsfree_audio_ref(void)
{
	ref_count += 1;

	if (ref_count != 1)
		return;

	if (!g_dbus_register_interface(ofono_dbus_get_connection(),
					"/", HFP_AUDIO_MANAGER_INTERFACE,
					am_methods, am_signals, NULL,
					NULL, NULL)) {
		ofono_error("Unable to register Handsfree Audio Manager");
		return;
	}

	modemwatch_id = __ofono_modemwatch_add(modem_watch, NULL, NULL);
}

void ofono_handsfree_audio_unref(void)
{
	if (ref_count == 0) {
		ofono_error("Error in handsfree audio manager ref counting");
		return;
	}

	ref_count -= 1;

	if (ref_count > 0)
		return;

	__ofono_modemwatch_remove(modemwatch_id);

	g_dbus_unregister_interface(ofono_dbus_get_connection(), "/",
						HFP_AUDIO_MANAGER_INTERFACE);

	if (agent) {
		agent_release(agent);
		agent_free(agent);
	}
}

int __ofono_handsfree_audio_manager_init(void)
{
	return 0;
}

void __ofono_handsfree_audio_manager_cleanup(void)
{
	if (ref_count == 0)
		return;

	ofono_error("Handsfree Audio manager not cleaned up properly,"
			"fixing...");

	ref_count = 1;
	ofono_handsfree_audio_unref();
}

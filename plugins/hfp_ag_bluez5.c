/*
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
#include <glib.h>
#include <ofono.h>

#define OFONO_API_SUBJECT_TO_CHANGE
#include <ofono/plugin.h>
#include <ofono/log.h>
#include <ofono/modem.h>
#include <gdbus.h>

#include "bluez5.h"

#ifndef DBUS_TYPE_UNIX_FD
#define DBUS_TYPE_UNIX_FD -1
#endif

#define HFP_AG_EXT_PROFILE_PATH   "/bluetooth/profile/hfp_ag"

#define HFP_VERSION_1_6		0x0106

struct hfp_ag {
	struct ofono_emulator *em;
	bdaddr_t local;
	bdaddr_t peer;
	guint sco_watch;
	GSList *endpoints;		/* Remote Media endpoints objects */
};

static guint modemwatch_id;
static GList *modems;
static GHashTable *sim_hash = NULL;
static GSList *hfp_ags;

static void free_hfp_ag(void *data)
{
	struct hfp_ag *hfp_ag = data;

	DBG("");

	if (hfp_ag == NULL)
		return;

	if (hfp_ag->sco_watch)
		g_source_remove(hfp_ag->sco_watch);

	g_slist_free_full(hfp_ag->endpoints,
					(GDestroyNotify) bt_endpoint_unref);

	hfp_ags = g_slist_remove(hfp_ags, hfp_ag);
	g_free(hfp_ag);
}

static DBusMessage *profile_new_connection(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessageIter entry;
	const char *device;
	int fd;
	guint16 version = 0;
	guint16 features = 0;
	GSList *endpoints = NULL;
	struct sockaddr_rc saddr;
	bdaddr_t local;
	bdaddr_t peer;
	socklen_t optlen;
	struct ofono_emulator *em;
	struct ofono_modem *modem;
	struct hfp_ag *hfp_ag;

	DBG("Profile handler NewConnection");

	if (dbus_message_iter_init(msg, &entry) == FALSE)
		goto invalid;

	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_OBJECT_PATH)
		goto invalid;

	dbus_message_iter_get_basic(&entry, &device);
	dbus_message_iter_next(&entry);

	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_UNIX_FD)
		goto invalid;

	dbus_message_iter_get_basic(&entry, &fd);
	dbus_message_iter_next(&entry);

	if (fd < 0)
		goto invalid;

	if (bt_parse_fd_properties(&entry, &version, &features, &endpoints) < 0)
		goto error;

	DBG("%s version: 0x%04x features: 0x%04x", device, version, features);

	memset(&saddr, 0, sizeof(saddr));
	optlen = sizeof(saddr);
	if (getsockname(fd, (struct sockaddr *) &saddr, &optlen) < 0) {
		ofono_error("RFCOMM getsockname(): %s (%d)", strerror(errno),
									errno);
		g_slist_free_full(endpoints, (GDestroyNotify)bt_endpoint_unref);
		goto error;
	}

	local = saddr.rc_bdaddr;

	memset(&saddr, 0, sizeof(saddr));
	optlen = sizeof(saddr);
	if (getpeername(fd, (struct sockaddr *) &saddr, &optlen) < 0) {
		ofono_error("RFCOMM getpeername(): %s (%d)", strerror(errno),
									errno);
		g_slist_free_full(endpoints, (GDestroyNotify)bt_endpoint_unref);
		goto error;
	}

	peer = saddr.rc_bdaddr;

	/* Pick the first voicecall capable modem */
	modem = modems->data;
	if (modem == NULL) {
		g_slist_free_full(endpoints,
					(GDestroyNotify) bt_endpoint_unref);
		close(fd);
		return g_dbus_create_error(msg, BLUEZ_ERROR_INTERFACE
						".Rejected",
						"No voice call capable modem");
	}

	DBG("Picked modem %p for emulator", modem);

	em = ofono_emulator_create(modem, OFONO_EMULATOR_TYPE_HFP);
	if (em == NULL) {
		g_slist_free_full(endpoints,
					(GDestroyNotify) bt_endpoint_unref);
		close(fd);
		return g_dbus_create_error(msg, BLUEZ_ERROR_INTERFACE
						".Rejected",
						"Not enough resources");
	}

	ofono_emulator_register(em, fd);

	hfp_ag = g_new0(struct hfp_ag, 1);
	hfp_ag->em = em;
	hfp_ag->local = local;
	hfp_ag->peer = peer;
	hfp_ag->endpoints = endpoints;
	ofono_emulator_set_data(em, hfp_ag, free_hfp_ag);

	hfp_ags = g_slist_append(hfp_ags, hfp_ag);

	return dbus_message_new_method_return(msg);

error:
	close(fd);

invalid:
	return g_dbus_create_error(msg, BLUEZ_ERROR_INTERFACE ".Rejected",
					"Invalid arguments in method call");
}

static DBusMessage *profile_release(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	DBG("Profile handler Release");

	return g_dbus_create_error(msg, BLUEZ_ERROR_INTERFACE
						".NotImplemented",
						"Implementation not provided");
}

static DBusMessage *profile_cancel(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	DBG("Profile handler Cancel");

	return g_dbus_create_error(msg, BLUEZ_ERROR_INTERFACE
					".NotImplemented",
					"Implementation not provided");
}

static DBusMessage *profile_disconnection(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	DBG("Profile handler RequestDisconnection");

	return g_dbus_create_error(msg, BLUEZ_ERROR_INTERFACE
					".NotImplemented",
					"Implementation not provided");
}

static const GDBusMethodTable profile_methods[] = {
	{ GDBUS_ASYNC_METHOD("NewConnection",
				GDBUS_ARGS({ "device", "o"}, { "fd", "h"},
						{ "fd_properties", "a{sv}" }),
				NULL, profile_new_connection) },
	{ GDBUS_METHOD("Release", NULL, NULL, profile_release) },
	{ GDBUS_METHOD("Cancel", NULL, NULL, profile_cancel) },
	{ GDBUS_METHOD("RequestDisconnection",
				GDBUS_ARGS({"device", "o"}), NULL,
				profile_disconnection) },
	{ }
};

static gboolean sco_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)

{
	struct hfp_ag *hfp_ag = user_data;
	char adapter_address[18];
	char device_address[18];

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
		hfp_ag->sco_watch = 0;

		bt_ba2str(&hfp_ag->local, adapter_address);
		bt_ba2str(&hfp_ag->peer, device_address);
		DBG("SCO: %s - %s (closed)", adapter_address, device_address);

		return FALSE;
	}

	return TRUE;
}

static gboolean hfp_ag_sco_accept(int fd, struct sockaddr_sco *raddr)
{
	struct sockaddr_sco laddr;
	socklen_t optlen;
	GSList *l;
	char adapter_address[18];
	char device_address[18];
	struct hfp_ag *hfp_ag = NULL;
	GIOChannel *sco_io;
	int err;

	memset(&laddr, 0, sizeof(laddr));
	optlen = sizeof(laddr);
	if (getsockname(fd, (struct sockaddr *) &laddr, &optlen) < 0) {
		err = errno;
		ofono_error("SCO getsockname(): %s (%d)", strerror(err), err);
		return FALSE;
	}

	for (l = hfp_ags; l; l = l->next) {
		struct hfp_ag *tmp = l->data;

		if (bt_bacmp(&laddr.sco_bdaddr, &tmp->local) != 0)
			continue;

		if (bt_bacmp(&raddr->sco_bdaddr, &tmp->peer) != 0)
			continue;

		hfp_ag = tmp;
		break;
	}

	if (!hfp_ag) {
		ofono_error("Rejecting SCO: SLC connection missing!");
		return FALSE;
	}

	bt_ba2str(&laddr.sco_bdaddr, adapter_address);
	bt_ba2str(&raddr->sco_bdaddr, device_address);
	DBG("SCO: %s < %s (incoming)", adapter_address, device_address);

	sco_io = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(sco_io, TRUE);
	g_io_channel_set_flags(sco_io, G_IO_FLAG_NONBLOCK, NULL);

	hfp_ag->sco_watch = g_io_add_watch(sco_io,
						G_IO_ERR | G_IO_HUP | G_IO_NVAL,
						sco_cb, hfp_ag);

	g_io_channel_unref(sco_io);

	return TRUE;
}

static void sim_state_watch(enum ofono_sim_state new_state, void *data)
{
	struct ofono_modem *modem = data;
	DBusConnection *conn = ofono_dbus_get_connection();

	if (new_state != OFONO_SIM_STATE_READY) {
		if (modems == NULL)
			return;

		modems = g_list_remove(modems, modem);
		if (modems != NULL)
			return;

		bt_unregister_sco_server(hfp_ag_sco_accept);
		bluetooth_unregister_profile(conn, HFP_AG_EXT_PROFILE_PATH);

		return;
	}

	if (__ofono_modem_find_atom(modem, OFONO_ATOM_TYPE_VOICECALL) == NULL)
		return;

	modems = g_list_append(modems, modem);

	if (modems->next != NULL)
		return;

	bluetooth_register_profile(conn, HFP_AG_UUID, HFP_VERSION_1_6,
					0, "hfp_ag", HFP_AG_EXT_PROFILE_PATH);

	bt_register_sco_server(hfp_ag_sco_accept);
}

static gboolean sim_watch_remove(gpointer key, gpointer value,
				gpointer user_data)
{
	struct ofono_sim *sim = key;

	ofono_sim_remove_state_watch(sim, GPOINTER_TO_UINT(value));

	return TRUE;
}

static void sim_watch(struct ofono_atom *atom,
				enum ofono_atom_watch_condition cond,
				void *data)
{
	struct ofono_sim *sim = __ofono_atom_get_data(atom);
	struct ofono_modem *modem = data;
	int watch;

	if (cond == OFONO_ATOM_WATCH_CONDITION_UNREGISTERED) {
		sim_state_watch(OFONO_SIM_STATE_NOT_PRESENT, modem);

		sim_watch_remove(sim, g_hash_table_lookup(sim_hash, sim), NULL);
		g_hash_table_remove(sim_hash, sim);

		return;
	}

	watch = ofono_sim_add_state_watch(sim, sim_state_watch, modem, NULL);
	g_hash_table_insert(sim_hash, sim, GUINT_TO_POINTER(watch));
	sim_state_watch(ofono_sim_get_state(sim), modem);
}

static void modem_watch(struct ofono_modem *modem, gboolean added, void *user)
{
	DBG("modem: %p, added: %d", modem, added);

	if (added == FALSE)
		return;

	__ofono_modem_add_atom_watch(modem, OFONO_ATOM_TYPE_SIM,
					sim_watch, modem, NULL);
}

static void call_modemwatch(struct ofono_modem *modem, void *user)
{
	modem_watch(modem, TRUE, user);
}

static int hfp_ag_init(void)
{
	DBusConnection *conn = ofono_dbus_get_connection();

	if (DBUS_TYPE_UNIX_FD < 0)
		return -EBADF;

	/* Registers External Profile handler */
	if (!g_dbus_register_interface(conn, HFP_AG_EXT_PROFILE_PATH,
					BLUEZ_PROFILE_INTERFACE,
					profile_methods, NULL,
					NULL, NULL, NULL)) {
		ofono_error("Register Profile interface failed: %s",
						HFP_AG_EXT_PROFILE_PATH);
		return -EIO;
	}

	sim_hash = g_hash_table_new(g_direct_hash, g_direct_equal);

	modemwatch_id = __ofono_modemwatch_add(modem_watch, NULL, NULL);
	__ofono_modem_foreach(call_modemwatch, NULL);

	return 0;
}

static void hfp_ag_exit(void)
{
	DBusConnection *conn = ofono_dbus_get_connection();

	__ofono_modemwatch_remove(modemwatch_id);
	g_dbus_unregister_interface(conn, HFP_AG_EXT_PROFILE_PATH,
						BLUEZ_PROFILE_INTERFACE);

	g_list_free(modems);
	g_hash_table_foreach_remove(sim_hash, sim_watch_remove, NULL);
	g_hash_table_destroy(sim_hash);
}

OFONO_PLUGIN_DEFINE(hfp_ag_bluez5, "Hands-Free Audio Gateway Profile Plugins",
				VERSION, OFONO_PLUGIN_PRIORITY_DEFAULT,
				hfp_ag_init, hfp_ag_exit)

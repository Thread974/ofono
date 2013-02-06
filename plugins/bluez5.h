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

#define BLUEZ_SERVICE			"org.bluez"
#define BLUEZ_MANAGER_PATH		"/"
#define BLUEZ_PROFILE_INTERFACE		BLUEZ_SERVICE ".Profile1"
#define BLUEZ_PROFILE_MGMT_INTERFACE	BLUEZ_SERVICE ".ProfileManager1"
#define BLUEZ_ADAPTER_INTERFACE		BLUEZ_SERVICE ".Adapter1"
#define BLUEZ_DEVICE_INTERFACE		BLUEZ_SERVICE ".Device1"
#define BLUEZ_ERROR_INTERFACE		BLUEZ_SERVICE ".Error"

#define HFP_HS_UUID	"0000111e-0000-1000-8000-00805f9b34fb"
#define HFP_AG_UUID	"0000111f-0000-1000-8000-00805f9b34fb"

#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH		31
#define PF_BLUETOOTH		AF_BLUETOOTH
#endif

#define BTPROTO_SCO		2

#define SOL_SCO			17

#ifndef SOL_BLUETOOTH
#define SOL_BLUETOOTH		274
#endif

#define BT_DEFER_SETUP		7

/* BD Address */
typedef struct {
	uint8_t b[6];
} __attribute__((packed)) bdaddr_t;

#define BDADDR_ANY   (&(bdaddr_t) {{0, 0, 0, 0, 0, 0}})

/* RFCOMM socket address */
struct sockaddr_rc {
	sa_family_t	rc_family;
	bdaddr_t	rc_bdaddr;
	uint8_t		rc_channel;
};

/* SCO socket address */
struct sockaddr_sco {
	sa_family_t	sco_family;
	bdaddr_t	sco_bdaddr;
};

/* SCO socket options */
#define SCO_OPTIONS	0x01

#define SCO_MODE_CVSD		0x00
#define SCO_MODE_TRANSPARENT	0x01
#define SCO_MODE_ENHANCED	0x02
struct sco_options {
	uint16_t mtu;
	uint8_t mode;
};

struct sco_coding {
	uint8_t format;
	uint16_t vid;
	uint16_t cid;
};

struct sco_options_enhanced {
	uint16_t mtu;
	uint8_t mode;
	struct sco_coding host;
	struct sco_coding air;
};

#define SCO_CONNINFO	0x02
struct sco_conninfo {
	uint16_t hci_handle;
	uint8_t  dev_class[3];
};

void bt_bacpy(bdaddr_t *dst, const bdaddr_t *src);

int bt_ba2str(const bdaddr_t *ba, char *str);

int bt_bacmp(const bdaddr_t *ba1, const bdaddr_t *ba2);

typedef gboolean (*bt_sco_accept_cb)(int fd, struct sockaddr_sco *saddr);

int bt_register_sco_server(bt_sco_accept_cb cb);
void bt_unregister_sco_server(bt_sco_accept_cb cb);

struct bt_endpoint;
struct bt_transport;

typedef void (*bt_initiate_audio)(struct bt_transport *transport,
							gpointer user_data);

struct bt_endpoint *bt_endpoint_ref(struct bt_endpoint *endpoint);
void bt_endpoint_unref(struct bt_endpoint *endpoint);

int bt_parse_fd_properties(DBusMessageIter *iter, uint16_t *version,
					uint16_t *features, GSList **endpoints);

guint8 *bt_endpoints_to_codecs(GSList *endpoints, int *len);

void bt_transport_mic_volume_changed(void *userdata);
void bt_transport_speaker_volume_changed(void *userdata);

struct bt_transport *bt_transport_new(const char *device,
					struct bt_endpoint *endpoint,
					bt_initiate_audio init_audio,
					gpointer user_data);

struct bt_transport *bt_transport_ref(struct bt_transport *transport);
void bt_transport_unref(struct bt_transport *transport);

struct bt_transport *bt_transport_by_codec(GSList *transports,
							guint8 codec);

int bt_transport_register(struct bt_transport *transport,
					DBusPendingCallNotifyFunction cb,
					gpointer user_data);

void bt_transport_unregister(struct bt_transport *transport);

gboolean bt_transport_set_channel(struct bt_transport *transport,
							GIOChannel *io);

int bluetooth_register_profile(DBusConnection *conn, const char *uuid,
					uint16_t version, uint16_t features,
					const char *name, const char *object);

void bluetooth_unregister_profile(DBusConnection *conn, const char *object);

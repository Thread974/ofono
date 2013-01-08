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

#include <stdint.h>
#include <netinet/in.h>

#define	BLUEZ_SERVICE			"org.bluez"
#define BLUEZ_MANAGER_PATH		"/"
#define BLUEZ_PROFILE_INTERFACE		BLUEZ_SERVICE ".Profile1"
#define BLUEZ_PROFILE_MGMT_INTERFACE	BLUEZ_SERVICE ".ProfileManager1"
#define BLUEZ_ADAPTER_INTERFACE		BLUEZ_SERVICE".Adapter1"
#define BLUEZ_DEVICE_INTERFACE		BLUEZ_SERVICE".Device1"
#define BLUEZ_ERROR_INTERFACE		BLUEZ_SERVICE ".Error"

#define HFP_HS_UUID	"0000111e-0000-1000-8000-00805f9b34fb"

#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH	31
#define PF_BLUETOOTH	AF_BLUETOOTH
#endif

#define BTPROTO_SCO	2

#define SOL_SCO		17

#ifndef SOL_BLUETOOTH
#define SOL_BLUETOOTH	274
#endif

#define BT_DEFER_SETUP	7

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

int bluetooth_register_profile(DBusConnection *conn, const char *uuid,
				uint16_t version, uint16_t features,
				const char *name, const char *object);

void bluetooth_unregister_profile(DBusConnection *conn, const char *object);

void bluetooth_iter_parse_properties(DBusMessageIter *array,
						const char *property, ...);

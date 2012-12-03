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

struct media_endpoint;
struct media_transport;

struct media_endpoint *media_endpoint_new(const char *owner,
					const char *path,
					guint8 codec,
					GArray *capabilities);


struct media_endpoint *media_endpoint_ref(struct media_endpoint *endpoint);
void media_endpoint_unref(struct media_endpoint *endpoint);

struct media_transport *media_transport_new(int id, const char *device,
					struct media_endpoint *endpoint);

struct media_transport *media_transport_ref(struct media_transport *transport);
void media_transport_unref(struct media_transport *transport);

int media_transport_register(struct media_transport *transport,
					DBusPendingCallNotifyFunction cb,
					gpointer user_data);

void media_transport_unregister(struct media_transport *transport);

gboolean media_transport_set_channel(struct media_transport *transport,
							GIOChannel *io);

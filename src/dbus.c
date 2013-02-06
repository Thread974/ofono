/*
 *
 *  oFono - Open Source Telephony
 *
 *  Copyright (C) 2008-2011  Intel Corporation. All rights reserved.
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

#include <glib.h>
#include <gdbus.h>

#include "ofono.h"

#define OFONO_ERROR_INTERFACE "org.ofono.Error"

struct property_handler {
	const char *property;
	property_handler_cb callback;
	void *user_data;
};

static DBusConnection *g_connection;

struct error_mapping_entry {
	int error;
	DBusMessage *(*ofono_error_func)(DBusMessage *);
};

struct error_mapping_entry cme_errors_mapping[] = {
	{ 3,	__ofono_error_not_allowed },
	{ 4,	__ofono_error_not_supported },
	{ 16,	__ofono_error_incorrect_password },
	{ 30,	__ofono_error_not_registered },
	{ 31,	__ofono_error_timed_out },
	{ 32,	__ofono_error_access_denied },
	{ 50,	__ofono_error_invalid_args },
};

static void append_variant(DBusMessageIter *iter,
				int type, void *value)
{
	char sig[2];
	DBusMessageIter valueiter;

	sig[0] = type;
	sig[1] = 0;

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
						sig, &valueiter);

	dbus_message_iter_append_basic(&valueiter, type, value);

	dbus_message_iter_close_container(iter, &valueiter);
}

void ofono_dbus_dict_append(DBusMessageIter *dict,
			const char *key, int type, void *value)
{
	DBusMessageIter keyiter;

	if (type == DBUS_TYPE_STRING) {
		const char *str = *((const char **) value);
		if (str == NULL)
			return;
	}

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
							NULL, &keyiter);

	dbus_message_iter_append_basic(&keyiter, DBUS_TYPE_STRING, &key);

	append_variant(&keyiter, type, value);

	dbus_message_iter_close_container(dict, &keyiter);
}

static void append_array_variant(DBusMessageIter *iter, int type, void *val,
							int n_elements)
{
	DBusMessageIter variant, array;
	char type_sig[2] = { type, '\0' };
	char array_sig[3] = { DBUS_TYPE_ARRAY, type, '\0' };

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
						array_sig, &variant);

	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY,
						type_sig, &array);

	if (dbus_type_is_fixed(type) == TRUE) {
		dbus_message_iter_append_fixed_array(&array, type, val,
							n_elements);
	} else if (type == DBUS_TYPE_STRING || type == DBUS_TYPE_OBJECT_PATH) {
		const char ***str_array = val;
		int i;

		for (i = 0; i < n_elements; i++)
			dbus_message_iter_append_basic(&array, type,
							&((*str_array)[i]));
	}

	dbus_message_iter_close_container(&variant, &array);

	dbus_message_iter_close_container(iter, &variant);
}

void ofono_dbus_dict_append_array(DBusMessageIter *dict, const char *key,
				int type, void *val, int n_elements)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
						NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	append_array_variant(&entry, type, val, n_elements);

	dbus_message_iter_close_container(dict, &entry);
}

static void append_dict_variant(DBusMessageIter *iter, int type, void *val)
{
	DBusMessageIter variant, array, entry;
	char typesig[5];
	char arraysig[6];
	const void **val_array = *(const void ***) val;
	int i;

	arraysig[0] = DBUS_TYPE_ARRAY;
	arraysig[1] = typesig[0] = DBUS_DICT_ENTRY_BEGIN_CHAR;
	arraysig[2] = typesig[1] = DBUS_TYPE_STRING;
	arraysig[3] = typesig[2] = type;
	arraysig[4] = typesig[3] = DBUS_DICT_ENTRY_END_CHAR;
	arraysig[5] = typesig[4] = '\0';

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
						arraysig, &variant);

	dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY,
						typesig, &array);

	for (i = 0; val_array[i]; i += 2) {
		dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY,
							NULL, &entry);

		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
						&(val_array[i + 0]));

		/*
		 * D-Bus expects a char** or uint8* depending on the type
		 * given. Since we are dealing with an array through a void**
		 * (and thus val_array[i] is a pointer) we need to
		 * differentiate DBUS_TYPE_STRING from the others. The other
		 * option would be the user to pass the exact type to this
		 * function, instead of a pointer to it. However in this case
		 * a cast from type to void* would be needed, which is not
		 * good.
		 */
		if (type == DBUS_TYPE_STRING) {
			dbus_message_iter_append_basic(&entry, type,
							&(val_array[i + 1]));
		} else {
			dbus_message_iter_append_basic(&entry, type,
							val_array[i + 1]);
		}

		dbus_message_iter_close_container(&array, &entry);
	}

	dbus_message_iter_close_container(&variant, &array);

	dbus_message_iter_close_container(iter, &variant);
}

void ofono_dbus_dict_append_dict(DBusMessageIter *dict, const char *key,
				int type, void *val)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
						NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	append_dict_variant(&entry, type, val);

	dbus_message_iter_close_container(dict, &entry);
}

int ofono_dbus_signal_property_changed(DBusConnection *conn,
					const char *path,
					const char *interface,
					const char *name,
					int type, void *value)
{
	DBusMessage *signal;
	DBusMessageIter iter;

	signal = dbus_message_new_signal(path, interface, "PropertyChanged");
	if (signal == NULL) {
		ofono_error("Unable to allocate new %s.PropertyChanged signal",
				interface);
		return -1;
	}

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &name);

	append_variant(&iter, type, value);

	return g_dbus_send_message(conn, signal);
}

int ofono_dbus_signal_array_property_changed(DBusConnection *conn,
						const char *path,
						const char *interface,
						const char *name,
						int type, void *value,
						int n_elements)

{
	DBusMessage *signal;
	DBusMessageIter iter;

	signal = dbus_message_new_signal(path, interface, "PropertyChanged");
	if (signal == NULL) {
		ofono_error("Unable to allocate new %s.PropertyChanged signal",
				interface);
		return -1;
	}

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &name);

	append_array_variant(&iter, type, value, n_elements);

	return g_dbus_send_message(conn, signal);
}

int ofono_dbus_signal_dict_property_changed(DBusConnection *conn,
						const char *path,
						const char *interface,
						const char *name,
						int type, void *value)

{
	DBusMessage *signal;
	DBusMessageIter iter;

	signal = dbus_message_new_signal(path, interface, "PropertyChanged");
	if (signal == NULL) {
		ofono_error("Unable to allocate new %s.PropertyChanged signal",
				interface);
		return -1;
	}

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &name);

	append_dict_variant(&iter, type, value);

	return g_dbus_send_message(conn, signal);
}

static gint property_handler_compare(gconstpointer a, gconstpointer b)
{
	const struct property_handler *handler = a;
	const char *property = b;

	return g_strcmp0(handler->property, property);
}

void ofono_dbus_iter_parse_properties(DBusMessageIter *array,
				const char *property, property_handler_cb cb,
				void *user_data, ...)
{
	va_list args;
	GSList *prop_handlers = NULL;
	DBusMessageIter dict;

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		goto done;

	va_start(args, user_data);

	if (property == NULL)
		return;

	while (1) {
		struct property_handler *handler =
					g_new0(struct property_handler, 1);

		handler->property = property;
		handler->callback = cb;
		handler->user_data = user_data;

		prop_handlers = g_slist_prepend(prop_handlers, handler);

		property = va_arg(args, const char *);
		if (property == NULL)
			break;

		cb = va_arg(args, property_handler_cb);
		user_data = va_arg(args, void *);
	}

	va_end(args);

	dbus_message_iter_recurse(array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;
		GSList *l;

		dbus_message_iter_recurse(&dict, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			goto done;

		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			goto done;

		dbus_message_iter_recurse(&entry, &value);

		l = g_slist_find_custom(prop_handlers, key,
					property_handler_compare);

		if (l) {
			struct property_handler *handler = l->data;

			handler->callback(&value, handler->user_data);
		}

		dbus_message_iter_next(&dict);
	}

done:
	g_slist_foreach(prop_handlers, (GFunc) g_free, NULL);
	g_slist_free(prop_handlers);
}

DBusMessage *__ofono_error_invalid_args(DBusMessage *msg)
{
	return g_dbus_create_error(msg, OFONO_ERROR_INTERFACE
					".InvalidArguments",
					"Invalid arguments in method call");
}

DBusMessage *__ofono_error_invalid_format(DBusMessage *msg)
{
	return g_dbus_create_error(msg, OFONO_ERROR_INTERFACE
					".InvalidFormat",
					"Argument format is not recognized");
}

DBusMessage *__ofono_error_not_implemented(DBusMessage *msg)
{
	return g_dbus_create_error(msg, OFONO_ERROR_INTERFACE
					".NotImplemented",
					"Implementation not provided");
}

DBusMessage *__ofono_error_failed(DBusMessage *msg)
{
	return g_dbus_create_error(msg, OFONO_ERROR_INTERFACE ".Failed",
					"Operation failed");
}

DBusMessage *__ofono_error_busy(DBusMessage *msg)
{
	return g_dbus_create_error(msg, OFONO_ERROR_INTERFACE ".InProgress",
					"Operation already in progress");
}

DBusMessage *__ofono_error_not_found(DBusMessage *msg)
{
	return g_dbus_create_error(msg, OFONO_ERROR_INTERFACE ".NotFound",
			"Object is not found or not valid for this operation");
}

DBusMessage *__ofono_error_not_active(DBusMessage *msg)
{
	return g_dbus_create_error(msg, OFONO_ERROR_INTERFACE ".NotActive",
			"Operation is not active or in progress");
}

DBusMessage *__ofono_error_not_supported(DBusMessage *msg)
{
	return g_dbus_create_error(msg, OFONO_ERROR_INTERFACE
					".NotSupported",
					"Operation is not supported by the"
					" network / modem");
}

DBusMessage *__ofono_error_not_available(DBusMessage *msg)
{
	return g_dbus_create_error(msg, OFONO_ERROR_INTERFACE
					".NotAvailable",
					"Operation currently not available");
}

DBusMessage *__ofono_error_timed_out(DBusMessage *msg)
{
	return g_dbus_create_error(msg, OFONO_ERROR_INTERFACE ".Timedout",
			"Operation failure due to timeout");
}

DBusMessage *__ofono_error_sim_not_ready(DBusMessage *msg)
{
	return g_dbus_create_error(msg, OFONO_ERROR_INTERFACE ".SimNotReady",
			"SIM is not ready or not inserted");
}

DBusMessage *__ofono_error_in_use(DBusMessage *msg)
{
	return g_dbus_create_error(msg, OFONO_ERROR_INTERFACE ".InUse",
			"The resource is currently in use");
}

DBusMessage *__ofono_error_not_attached(DBusMessage *msg)
{
	return g_dbus_create_error(msg, OFONO_ERROR_INTERFACE ".NotAttached",
			"GPRS is not attached");
}

DBusMessage *__ofono_error_attach_in_progress(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
				OFONO_ERROR_INTERFACE ".AttachInProgress",
				"GPRS Attach is in progress");
}

DBusMessage *__ofono_error_not_registered(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
				OFONO_ERROR_INTERFACE ".NotRegistered",
				"Modem is not registered to the network");
}

DBusMessage *__ofono_error_canceled(DBusMessage *msg)
{
	return g_dbus_create_error(msg, OFONO_ERROR_INTERFACE ".Canceled",
					"Operation has been canceled");
}

DBusMessage *__ofono_error_access_denied(DBusMessage *msg)
{
	return g_dbus_create_error(msg, OFONO_ERROR_INTERFACE ".AccessDenied",
					"Operation not permitted");
}

DBusMessage *__ofono_error_emergency_active(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
				OFONO_ERROR_INTERFACE ".EmergencyActive",
				"Emergency mode active");
}

DBusMessage *__ofono_error_incorrect_password(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
				OFONO_ERROR_INTERFACE ".IncorrectPassword",
				"Password is incorrect");
}

DBusMessage *__ofono_error_not_allowed(DBusMessage *msg)
{
	return g_dbus_create_error(msg, OFONO_ERROR_INTERFACE ".NotAllowed",
					"Operation is not allowed");
}

DBusMessage *__ofono_error_not_recognized(DBusMessage *msg)
{
	return g_dbus_create_error(msg, OFONO_ERROR_INTERFACE ".NotRecognized",
					"String not recognized as USSD/SS");
}

DBusMessage *__ofono_error_network_terminated(DBusMessage *msg)
{
	return g_dbus_create_error(msg, OFONO_ERROR_INTERFACE
					".Terminated",
					"Operation was terminated by the"
					" network");
}

DBusMessage *__ofono_error_from_error(const struct ofono_error *error,
						DBusMessage *msg)
{
	struct error_mapping_entry *e;
	int maxentries;
	int i;

	switch (error->type) {
	case OFONO_ERROR_TYPE_CME:
		e = cme_errors_mapping;
		maxentries = sizeof(cme_errors_mapping) /
					sizeof(struct error_mapping_entry);
		for (i = 0; i < maxentries; i++)
			if (e[i].error == error->error)
				return e[i].ofono_error_func(msg);
		break;
	case OFONO_ERROR_TYPE_CMS:
		return __ofono_error_failed(msg);
	case OFONO_ERROR_TYPE_CEER:
		return __ofono_error_failed(msg);
	default:
		return __ofono_error_failed(msg);
	}

	return __ofono_error_failed(msg);
}

void __ofono_dbus_pending_reply(DBusMessage **msg, DBusMessage *reply)
{
	DBusConnection *conn = ofono_dbus_get_connection();

	g_dbus_send_message(conn, reply);

	dbus_message_unref(*msg);
	*msg = NULL;
}

gboolean __ofono_dbus_valid_object_path(const char *path)
{
	unsigned int i;
	char c = '\0';

	if (path == NULL)
		return FALSE;

	if (path[0] == '\0')
		return FALSE;

	if (path[0] && !path[1] && path[0] == '/')
		return TRUE;

	if (path[0] != '/')
		return FALSE;

	for (i = 0; path[i]; i++) {
		if (path[i] == '/' && c == '/')
			return FALSE;

		c = path[i];

		if (path[i] >= 'a' && path[i] <= 'z')
			continue;

		if (path[i] >= 'A' && path[i] <= 'Z')
			continue;

		if (path[i] >= '0' && path[i] <= '9')
			continue;

		if (path[i] == '_' || path[i] == '/')
			continue;

		return FALSE;
	}

	if (path[i-1] == '/')
		return FALSE;

	return TRUE;
}

DBusConnection *ofono_dbus_get_connection(void)
{
	return g_connection;
}

static void dbus_gsm_set_connection(DBusConnection *conn)
{
	if (conn && g_connection != NULL)
		ofono_error("Setting a connection when it is not NULL");

	g_connection = conn;
}

int __ofono_dbus_init(DBusConnection *conn)
{
	dbus_gsm_set_connection(conn);

	return 0;
}

void __ofono_dbus_cleanup(void)
{
	DBusConnection *conn = ofono_dbus_get_connection();

	if (conn == NULL || !dbus_connection_get_is_connected(conn))
		return;

	dbus_gsm_set_connection(NULL);
}

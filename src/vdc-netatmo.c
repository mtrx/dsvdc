/*
    Copyright (c) 2014 Michael Tross
    Author: Michael Tross <michael@tross.org>

    This file is part of digitalStrom NetAtmo Virtual Device and needs
    libdSvDC from https://gitorious.digitalstrom.org/virtual-devices/libdsvdc.

    digitalStrom NetAtmo Virtual Device is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    libdsvdc is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with digitalSTROM Server. If not, see <http://www.gnu.org/licenses/>.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libconfig.h>
#include <curl/curl.h>
#include <json/json.h>
#include <utlist.h>

#include <dsvdc/dsvdc.h>

#define MAX_MODULES 5
#define MAX_VALUES 5

typedef struct netatmo_value {
	char *data_type;
	double value;
	double last_value;
	time_t last_query;
	time_t last_reported;
} netatmo_value_t;

typedef struct netatmo_module {
	char *id;
	char *name;
	time_t last_message;
	time_t last_seen;
	int values_num;
	netatmo_value_t values[MAX_VALUES];

	unsigned char bid_length;
	unsigned char bid[16];
} netatmo_module_t;

typedef struct netatmo_base {
	char *station_name;
	char *bssid;
	double location_x;
	double location_y;
	double location_alt;
	int modules_num;
	netatmo_module_t modules[MAX_MODULES];
} netatmo_base_t;

typedef struct netatmo_data {
	char *dsuid;
	char *username;
	char *password;
	char *authcode;
	netatmo_base_t base;
} netatmo_data_t;

typedef struct netatmo_vdcd {
	struct netatmo_vdcd* next;
	char dsuid[136 / 8 * 2 + 1];
	char *id;
	int announced;
	int present;
	netatmo_module_t* mod;
} netatmo_vdcd_t;

static netatmo_data_t netatmo;
static netatmo_vdcd_t* devlist = NULL;

struct memory_struct {
	char *memory;
	size_t size;
};

#define NETATMO_OUT_OF_MEMORY -1
#define NETATMO_AUTH_FAILED -10
#define NETATMO_BAD_CONFIG -12
#define NETATMO_DEVLIST_FAILED -13
#define NETATMO_GETMEASURE_FAILED -13

static const char *g_cfgfile = "netatmo.cfg";
static const char *g_client_id = "52823f931877590c917b23f7";
static const char *g_client_secret = NULL;
static char *g_access_token = NULL;
static char *g_refresh_token = NULL;
static time_t g_refresh_token_valid_until = 0;
static time_t g_resync_devices = 60 * 60;
static time_t g_refresh_values = 5 * 60;
static char *g_vdc_dsuid = "3504175FE0000000BC514CBE";
static int g_shutdown_flag = 0;


/*******************************************************************/

int read_config()
{
	config_t config;
	struct stat statbuf;
	int n, v;
	char *sval;

	if (stat(g_cfgfile, &statbuf) != 0) {
		fprintf(stderr, "Could not find configuration file %s\n", g_cfgfile);
		return -1;
	}
	if (!S_ISREG(statbuf.st_mode)) {
		fprintf(stderr, "Configuration file \"%s\" is not a regular file", g_cfgfile);
		return -1;
	}

	config_init(&config);
	if (!config_read_file(&config, g_cfgfile)) {
		fprintf(stderr, "Error in configuration: l.%d %s\n",
				config_error_line(&config), config_error_text(&config));
		config_destroy(&config);
		return -1;
	}

	if (config_lookup_string(&config, "secret", (const char **) &sval))
		g_client_secret = strdup(sval);
	if (config_lookup_string(&config, "username", (const char **) &sval))
		netatmo.username = strdup(sval);
	if (config_lookup_string(&config, "password", (const char **) &sval))
		netatmo.password = strdup(sval);
	if (config_lookup_string(&config, "authcode", (const char **) &sval))
		netatmo.authcode = strdup(sval);
	config_lookup_int(&config, "resync_devices", (int *) &g_resync_devices);
	config_lookup_int(&config, "refresh_values", (int *) &g_refresh_values);

	if (config_lookup_string(&config, "device.station_name", (const char **) &sval))
		netatmo.base.station_name = strdup(sval);
	if (config_lookup_string(&config, "device.bssid", (const char **) &sval))
		netatmo.base.bssid = strdup(sval);
	config_lookup_float(&config, "device.location_x", &netatmo.base.location_x);
	config_lookup_float(&config, "device.location_y", &netatmo.base.location_y);
	config_lookup_float(&config, "device.altitude", &netatmo.base.location_alt);
	config_lookup_int(&config, "device.modules", (int *) &netatmo.base.modules_num);

	if (netatmo.base.modules_num > MAX_MODULES) {
		netatmo.base.modules_num = MAX_MODULES;
	}

	for (n = 0; n < netatmo.base.modules_num; n++) {
		char path[128];
		netatmo_module_t* module = &netatmo.base.modules[n];

		sprintf(path, "module.m%d.name", n);
		if (config_lookup_string(&config, path, (const char **) &sval))
			module->name = strdup(sval);
		sprintf(path, "module.m%d.id", n);
		if (config_lookup_string(&config, path, (const char **) &sval))
			module->id = strdup(sval);
		sprintf(path, "module.m%d.last_message", n);
		config_lookup_int(&config, path, (int *) &module->last_message);
		sprintf(path, "module.m%d.last_seen", n);
		config_lookup_int(&config, path, (int *) &module->last_seen);
		sprintf(path, "module.m%d.values", n);
		config_lookup_int(&config, path, (int *) &module->values_num);

		if (module->values_num > MAX_VALUES) {
			module->values_num = MAX_VALUES;
		}

		for (v = 0; v < module->values_num; v++) {
			netatmo_value_t* value = &module->values[v];

			sprintf(path, "module.m%d.v%d.data_type", n, v);
			if (config_lookup_string(&config, path, (const char **) &sval))
				value->data_type = strdup(sval);
			sprintf(path, "module.m%d.v%d.last_reported", n, v);
			config_lookup_int(&config, path, (int *) &value->last_reported);
			sprintf(path, "module.m%d.v%d.last_value", n, v);
			config_lookup_float(&config, path, &value->last_value);
		}
	}

	if (g_cfgfile != NULL ) {
		config_destroy(&config);
	}

	// cleanup old list
	devlist = NULL;

	netatmo_vdcd_t* dev;
	for (n = 0; n < MAX_MODULES; n++) {
		netatmo_module_t* m = &netatmo.base.modules[n];

		if (m->id) {
			int found = 0;
			LL_FOREACH(devlist, dev) {
				if (m->id && (strcmp(m->id, dev->id) == 0)) {
					found = 1; break;
				}
			}
			if (found == 0) {
				dev = malloc(sizeof(netatmo_vdcd_t));
				if (!dev) {
					return NETATMO_OUT_OF_MEMORY;
				}
				memset(dev, 0, sizeof(netatmo_vdcd_t));
			}

			dev->id = strdup(m->id);
			dev->present = false;
			dev->mod = m;

			char *p = dev->dsuid;
			strcpy(p, "3504175FE0AA");
			p += 12;
			for (v = 0; v < 6; v ++) {
				p += sprintf(p, "%02X", m->bid[v]);
			}

			if (!found) {
				LL_APPEND(devlist, dev);
			}
		}
	}

	return 0;
}

int write_config()
{
	config_t config;
	config_setting_t* cfg_root;
	config_setting_t* setting;
	config_setting_t* devicesetting;
	config_setting_t* modulesetting;
	int n, v;

	config_init(&config);
	cfg_root = config_root_setting(&config);

	setting = config_setting_add(cfg_root, "secret", CONFIG_TYPE_STRING);
	if (setting == NULL ) {
		setting = config_setting_get_member(cfg_root, "secret");
	}
	config_setting_set_string(setting, g_client_secret);

	setting = config_setting_add(cfg_root, "username", CONFIG_TYPE_STRING);
	if (setting == NULL ) {
		setting = config_setting_get_member(cfg_root, "username");
	}
	config_setting_set_string(setting, netatmo.username);

	setting = config_setting_add(cfg_root, "password", CONFIG_TYPE_STRING);
	if (setting == NULL ) {
		setting = config_setting_get_member(cfg_root, "password");
	}
	config_setting_set_string(setting, netatmo.password);

	setting = config_setting_add(cfg_root, "authcode", CONFIG_TYPE_STRING);
	if (setting == NULL ) {
		setting = config_setting_get_member(cfg_root, "authcode");
	}
	config_setting_set_string(setting, netatmo.authcode);

	devicesetting = config_setting_add(cfg_root, "device", CONFIG_TYPE_GROUP);

	setting = config_setting_add(devicesetting, "bssid", CONFIG_TYPE_STRING);
	if (setting == NULL ) {
		setting = config_setting_get_member(devicesetting, "bssid");
	}
	config_setting_set_string(setting, netatmo.base.bssid);

	setting = config_setting_add(devicesetting, "station_name", CONFIG_TYPE_STRING);
	if (setting == NULL ) {
		setting = config_setting_get_member(devicesetting, "station_name");
	}
	config_setting_set_string(setting, netatmo.base.station_name);

	setting = config_setting_add(devicesetting, "location_x", CONFIG_TYPE_FLOAT);
	if (setting == NULL ) {
		setting = config_setting_get_member(devicesetting, "location_x");
	}
	config_setting_set_float(setting, netatmo.base.location_x);

	setting = config_setting_add(devicesetting, "location_y", CONFIG_TYPE_FLOAT);
	if (setting == NULL ) {
		setting = config_setting_get_member(devicesetting, "location_y");
	}
	config_setting_set_float(setting, netatmo.base.location_y);

	setting = config_setting_add(devicesetting, "location_alt", CONFIG_TYPE_FLOAT);
	if (setting == NULL ) {
		setting = config_setting_get_member(devicesetting, "location_alt");
	}
	config_setting_set_float(setting, netatmo.base.location_alt);

	setting = config_setting_add(devicesetting, "modules", CONFIG_TYPE_INT);
	if (setting == NULL ) {
		setting = config_setting_get_member(devicesetting, "modules");
	}
	config_setting_set_int(setting, netatmo.base.modules_num);

	modulesetting = config_setting_add(cfg_root, "module", CONFIG_TYPE_GROUP);

	for (n = 0; n < netatmo.base.modules_num; n++) {
		char path[128];
		netatmo_module_t* module = &netatmo.base.modules[n];

		sprintf(path, "m%d", n);
		config_setting_t *s = config_setting_add(modulesetting, path, CONFIG_TYPE_GROUP);
		if (s == NULL ) {
			s = config_setting_get_member(modulesetting, path);
		}

		setting = config_setting_add(s, "name", CONFIG_TYPE_STRING);
		if (setting == NULL ) {
			setting = config_setting_get_member(s, "name");
		}
		config_setting_set_string(setting, module->name);

		setting = config_setting_add(s, "id", CONFIG_TYPE_STRING);
		if (setting == NULL ) {
			setting = config_setting_get_member(s, "id");
		}
		config_setting_set_string(setting, module->id);

		setting = config_setting_add(s, "last_message", CONFIG_TYPE_INT);
		if (setting == NULL ) {
			setting = config_setting_get_member(s, "last_message");
		}
		config_setting_set_int(setting, module->last_message);

		setting = config_setting_add(s, "last_seen", CONFIG_TYPE_INT);
		if (setting == NULL ) {
			setting = config_setting_get_member(s, "last_seen");
		}
		config_setting_set_int(setting, module->last_seen);

		setting = config_setting_add(s, "values", CONFIG_TYPE_INT);
		if (setting == NULL ) {
			setting = config_setting_get_member(s, "values");
		}
		config_setting_set_int(setting, module->values_num);

		for (v = 0; v < module->values_num; v++) {
			netatmo_value_t* value = &netatmo.base.modules[n].values[v];

			sprintf(path, "v%d", v);
			config_setting_t *v = config_setting_add(s, path, CONFIG_TYPE_GROUP);
			if (v == NULL) {
				v = config_setting_get_member(modulesetting, path);
			}

			setting = config_setting_add(v, "data_type", CONFIG_TYPE_STRING);
			if (setting == NULL ) {
				setting = config_setting_get_member(v, "data_type");
			}
			config_setting_set_string(setting, value->data_type);

			setting = config_setting_add(v, "last_reported", CONFIG_TYPE_INT);
			if (setting == NULL ) {
				setting = config_setting_get_member(v, "last_reported");
			}
			config_setting_set_int(setting, value->last_reported);

			setting = config_setting_add(v, "last_value", CONFIG_TYPE_FLOAT);
			if (setting == NULL ) {
				setting = config_setting_get_member(v, "last_value");
			}
			config_setting_set_float(setting, value->value);
		}
	}

	char tmpfile[PATH_MAX];
	sprintf(tmpfile, "%s.cfg", g_cfgfile);

	int ret = config_write_file(&config, tmpfile);
	if (!ret) {
		fprintf(stderr, "Error while writing new configuration file %s\n", tmpfile);
		unlink(tmpfile);
	} else {
		rename(tmpfile, g_cfgfile);
	}

	config_destroy(&config);
	return 0;
}

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct memory_struct *mem = (struct memory_struct *) userp;

	mem->memory = realloc(mem->memory, mem->size + realsize + 1);
	if (mem->memory == NULL )
	{
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
	return realsize;
}

struct memory_struct* query(const char *url, const char *postthis)
{
	CURL *curl;
	CURLcode res;
	struct memory_struct *chunk;

	chunk = malloc(sizeof(struct memory_struct));
	if (chunk == NULL)
	{
		printf("not enough memory\n");
		return NULL;
	}
	chunk->memory = malloc(1);
	chunk->size = 0;

	curl = curl_easy_init();
	if (curl == NULL)
	{
		printf("curl init failure\n");
		free(chunk->memory);
		free(chunk);
		return NULL;
	}
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void * )chunk);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postthis);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long )strlen(postthis));

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
	}
	curl_easy_cleanup(curl);

	if (res != CURLE_OK) {
		free(chunk->memory);
		free(chunk);
		return NULL;
	}
	return chunk;
}

/*******************************************************************/

int netatmo_get_token()
{
	struct memory_struct *response = NULL;

	if (g_refresh_token != NULL) {
		char request_body[1024];
		strcpy(request_body, "grant_type=refresh_token&client_id=");
		strcat(request_body, g_client_id);
		strcat(request_body, "&client_secret=");
		strcat(request_body, g_client_secret);
		strcat(request_body, "&refresh_token=");
		strcat(request_body, g_refresh_token);

		printf("Refresh access token\n");
		response = query("https://api.netatmo.net/oauth2/token", request_body);
		if (response == NULL ) {
			printf("NetAtmo authcode failure");
			return NETATMO_AUTH_FAILED;
		}

		// invalidate refresh token
		free(g_refresh_token);
		g_refresh_token = NULL;
	} else if (netatmo.authcode && strlen(netatmo.authcode) > 0) {
		char request_body[1024];
		strcpy(request_body, "grant_type=authorization_code&client_id=");
		strcat(request_body, g_client_id);
		strcat(request_body, "&client_secret=");
		strcat(request_body, g_client_secret);
		strcat(request_body, "&code=");
		strcat(request_body, netatmo.authcode);

		printf("Get access token with auth code\n");
		response = query("https://api.netatmo.net/oauth2/token", request_body);
		if (response == NULL ) {
			printf("NetAtmo authcode failure");
			return NETATMO_AUTH_FAILED;
		}
	} else if (netatmo.username && netatmo.password) {
		char request_body[1024];
		strcpy(request_body, "grant_type=password&client_id=");
		strcat(request_body, g_client_id);
		strcat(request_body, "&client_secret=");
		strcat(request_body, g_client_secret);
		strcat(request_body, "&username=");
		strcat(request_body, netatmo.username);
		strcat(request_body, "&password=");
		strcat(request_body, netatmo.password);

		printf("Get access token with username and password\n");
		response = query("https://api.netatmo.net/oauth2/token", request_body);
		if (response == NULL ) {
			printf("NetAtmo password failure");
			return NETATMO_AUTH_FAILED;
		}
	} else {
		return NETATMO_BAD_CONFIG;
	}

	json_object *jobj = json_tokener_parse(response->memory);
	json_object_object_foreach(jobj, key, val) {
		enum json_type type = val ? json_object_get_type(val) : 0;

		if (!strcmp(key, "access_token")) {
			if (type == json_type_string) {
				if (g_access_token) free(g_access_token);
				g_access_token = strdup(json_object_get_string(val));
			}
		} else if (!strcmp(key, "refresh_token")) {
			if (type == json_type_string) {
				if (g_refresh_token) free(g_refresh_token);
				g_refresh_token = strdup(json_object_get_string(val));
			}
		} else if (!strcmp(key, "expires_in")) {
			if (type == json_type_int) {
				int exp = json_object_get_int(val);
				g_refresh_token_valid_until = time(NULL) + exp - 120; // 2 minutes before expiration
			}
		} else {
			printf("Unknown key: %s\n", key);
		}
	}

	free(response->memory);
	free(response);
	return 0;
}

int netatmo_get_devices()
{
	int rc, n, nd, v;

	printf("Reading device list from NetAtmo\n");

	if (!g_access_token) {
		if ((rc = netatmo_get_token()) != 0) {
			return rc;
		}
	}

	char request_body[1024];
	strcpy(request_body, "access_token=");
	strcat(request_body, g_access_token);

	struct memory_struct *response = query(
			"https://api.netatmo.net/api/devicelist", request_body);
	if (response == NULL ) {
		printf("NetAtmo getting device list failed");
		return NETATMO_DEVLIST_FAILED;
	}

	for (n = 0; n < MAX_MODULES; n++) {
		netatmo_module_t* nmodule = &netatmo.base.modules[n];
		if (nmodule->id) free(nmodule->id);
		if (nmodule->name) free(nmodule->name);
		for (v = 0; v < MAX_VALUES; v++) {
			if (nmodule->values[v].data_type) free(nmodule->values[v].data_type);
		}
	}
	memset(netatmo.base.modules, 0, sizeof(netatmo_module_t) * MAX_MODULES);

	json_object *jobj = json_tokener_parse(response->memory);
	json_object_object_foreach(jobj, key, val) {
		enum json_type type = json_object_get_type(val);
		//printf("key %s, type %d\n", key, type);

		if (!strcmp(key, "status")) {
			if (type == json_type_string) {
				if (strcmp("ok", json_object_get_string(val)) != 0) {
					printf("NetAtmo returned status: %s\n", json_object_get_string(val));
					break;
				}
			}
		} else if (!strcmp(key, "body")) {
			if (type == json_type_object) {
				json_object *jobj2 = val;
				json_object_object_foreach(jobj2, key, val) {
					enum json_type type = val ? json_object_get_type(val) : -1;
					//printf("  key %s, type %d\n", key, type);

					if (!strcmp(key, "devices")) {
						if (type == json_type_array) {
							//array_list* dev = json_object_get_array(val);
							netatmo_module_t* nmodule = &netatmo.base.modules[0];

							for (n = 0; n < 1 /*dev->length*/; n++) {
								json_object* jobj3 = json_object_array_get_idx(val, n);
								json_object_object_foreach(jobj3, key, val) {
									enum json_type type = val ? json_object_get_type(val) : -1;
									//printf("    key %s, type %d\n", key, type);

									if (!strcmp(key, "_id") && (type == json_type_string)) {
										nmodule->id = strdup(json_object_get_string(val));
									} else if (!strcmp(key, "last_message") && (type == json_type_string)) {
										nmodule->last_message = json_object_get_int(val);
									} else if (!strcmp(key, "last_seen") && (type == json_type_string)) {
										nmodule->last_seen = json_object_get_int(val);
									} else if (!strcmp(key, "place") && (type == json_type_object)) {
										json_object *jobj4 = val;
										json_object_object_foreach(jobj4, key, val) {
											enum json_type type = val ? json_object_get_type(val) : -1;
											//printf("    key %s, type %d\n", key, type);

											if (!strcmp(key, "altitude") && type == json_type_string) {
												netatmo.base.location_alt = json_object_get_int(val);
											} else if (!strcmp(key, "bssid") && type == json_type_string) {
												if (netatmo.base.bssid) free(netatmo.base.bssid);
												netatmo.base.bssid = strdup(json_object_get_string(val));
											} else if (!strcmp(key, "location") && (type == json_type_array)) {
												array_list* location = json_object_get_array(val);
												if (location->length == 2) {
													json_object* jobj_x = json_object_array_get_idx(val, 0);
													json_object* jobj_y = json_object_array_get_idx(val, 1);
													netatmo.base.location_x = json_object_get_double(jobj_x);
													netatmo.base.location_y = json_object_get_double(jobj_y);
												}
											}
										}
									} else if (!strcmp(key, "station_name")) {
										if (type == json_type_string) {
											if (netatmo.base.station_name) free(netatmo.base.station_name);
											netatmo.base.station_name = strdup(json_object_get_string(val));
										}
									} else if (!strcmp(key, "module_name")) {
										if (type == json_type_string) {
											nmodule->name = strdup(json_object_get_string(val));
										}
									} else if (!strcmp(key, "data_type") && (type == json_type_array)) {
										array_list* dtypes = json_object_get_array(val);

										netatmo_value_t* vmodule = &nmodule->values[0];
										nmodule->values_num = dtypes->length > MAX_VALUES ? MAX_VALUES : dtypes->length;

										for (nd = 0; nd < nmodule->values_num; nd++) {
											json_object* jobj4 = json_object_array_get_idx(val, nd);
											enum json_type type = jobj4 ? json_object_get_type(jobj4) : -1;
											if (type == json_type_string) {
												vmodule[nd].data_type = strdup(json_object_get_string(jobj4));
											}
										}
									}

								}
							}
						}
					} else if (!strcmp(key, "modules")) {
						if (type == json_type_array) {
							array_list* mod = json_object_get_array(val);

							netatmo.base.modules_num = mod->length+1 > MAX_MODULES ? MAX_MODULES : mod->length+1;

							for (n = 0; n < mod->length; n++) {
								netatmo_module_t* nmodule = &netatmo.base.modules[1+n];

								json_object* jobj3 = json_object_array_get_idx(val, n);
								json_object_object_foreach(jobj3, key, val) {
									enum json_type type = val ? json_object_get_type(val) : -1;
									//printf("    key %s, type %d\n", key, type);

									if (!strcmp(key, "module_name") && (type == json_type_string)) {
										nmodule->name = strdup(json_object_get_string(val));
									} else if (!strcmp(key, "_id") && (type == json_type_string)) {
										nmodule->id = strdup(json_object_get_string(val));
									} else if (!strcmp(key, "last_message") && (type == json_type_string)) {
										nmodule->last_message = json_object_get_int(val);
									} else if (!strcmp(key, "last_seen") && (type == json_type_string)) {
										nmodule->last_seen = json_object_get_int(val);
									} else if (!strcmp(key, "data_type") && (type == json_type_array)) {
										array_list* dtypes = json_object_get_array(val);

										netatmo_value_t* vmodule = &nmodule->values[0];
										nmodule->values_num = dtypes->length > MAX_VALUES ? MAX_VALUES : dtypes->length;

										for (nd = 0; nd < nmodule->values_num; nd++) {
											json_object* jobj4 = json_object_array_get_idx(val, nd);
											enum json_type type = jobj4 ? json_object_get_type(jobj4) : -1;
											if (type == json_type_string) {
												vmodule[nd].data_type = strdup(json_object_get_string(jobj4));
											}
										}

									}

								}
							}
						}
					}
				}
			}
		}
	}

	netatmo_vdcd_t* dev;
	for (n = 0; n < MAX_MODULES; n++) {
		netatmo_module_t* m = &netatmo.base.modules[n];

		if (m->id) {
			unsigned char *mac = m->bid;
			m->bid_length = 6;
			sscanf(m->id, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

			int found = 0;
			LL_FOREACH(devlist, dev) {
				if (!strcmp(m->id, dev->id)) {
					found = 1; break;
				}
			}
			if (found == 0) {
				dev = malloc(sizeof(netatmo_vdcd_t));
				if (!dev) {
					return NETATMO_OUT_OF_MEMORY;
				}
				memset(dev, 0, sizeof(netatmo_vdcd_t));
				LL_APPEND(devlist, dev);
			}

			dev->id = strdup(m->id);
			dev->present = true;
			dev->mod = m;

			// TODO: add libdsvdc method to generate proper dsuid's

			char *p = dev->dsuid;
			strcpy(p, "3504175FE0AA");
			p += 12;
			for (v = 0; v < 6; v ++) {
				p += sprintf(p, "%02X", m->bid[v]);
			}
		}
	}

	free(response->memory);
	free(response);
	return 0;
}

int netatmo_get_values()
{
	int rc, n, v;
	time_t now;

	printf("Reading data values from NetAtmo\n");

	if (!g_access_token) {
		if ((rc = netatmo_get_token()) != 0) {
			return rc;
		}
	}

	for (n = 0; n < netatmo.base.modules_num; n ++) {
		netatmo_module_t* m = &netatmo.base.modules[n];

		char request_body[1024];
		strcpy(request_body, "access_token=");
		strcat(request_body, g_access_token);
		strcat(request_body, "&device_id=");
		strcat(request_body, netatmo.base.modules[0].id);
		strcat(request_body, "&module_id=");
		strcat(request_body, m->id);
		strcat(request_body, "&scale=max&type=Temperature,Humidity,Co2&date_end=last");

		struct memory_struct *response = query(
			"https://api.netatmo.net/api/getmeasure", request_body);
		if (response == NULL ) {
			printf("NetAtmo getting measurement failed");
			return NETATMO_GETMEASURE_FAILED;
		}
		now = time(NULL);

		json_object *jobj = json_tokener_parse(response->memory);
		json_object_object_foreach(jobj, key, val) {
			enum json_type type = json_object_get_type(val);
			//printf("key %s, type %d\n", key, type);

			if (!strcmp(key, "status")) {
				if (type == json_type_string) {
					if (strcmp("ok", json_object_get_string(val)) != 0) {
						printf("NetAtmo returned status: %s\n", json_object_get_string(val));
						break;
					}
				}

			} else if (!strcmp(key, "body")) {
				if (type == json_type_array) {
					json_object* jobj2 = json_object_array_get_idx(val, 0);
					json_object_object_foreach(jobj2, key, val) {
						enum json_type type = json_object_get_type(val);
						//printf(" -> key %s, type %d\n", key, type);

						if (!strcmp(key, "value") && (type == json_type_array)) {
							json_object* jobj3 = json_object_array_get_idx(val, 0);

							enum json_type type = json_object_get_type(jobj3);
							if (type == json_type_array) {
								array_list* va = json_object_get_array(jobj3);
								if (va->length >= 2) {
									json_object* jobj_t = json_object_array_get_idx(jobj3, 0);
									json_object* jobj_h = json_object_array_get_idx(jobj3, 1);
									for (v = 0; v < netatmo.base.modules[n].values_num; v++) {
										if (strcmp(netatmo.base.modules[n].values[v].data_type, "Temperature") == 0) {
											netatmo.base.modules[n].values[v].last_value = netatmo.base.modules[n].values[v].value;
											netatmo.base.modules[n].values[v].value = json_object_get_double(jobj_t);
											netatmo.base.modules[n].values[v].last_query = now;
										}
										if (strcmp(netatmo.base.modules[n].values[v].data_type, "Humidity") == 0) {
											netatmo.base.modules[n].values[v].last_value = netatmo.base.modules[n].values[v].value;
											netatmo.base.modules[n].values[v].value = json_object_get_double(jobj_h);
											netatmo.base.modules[n].values[v].last_query = now;
										}
									}
								}
							}
						}
					}
				}

			} else if (!strcmp(key, "error")) {
				if (type == json_type_object) {
					json_object *jobj2 = val;
					json_object_object_foreach(jobj2, key, val) {
						enum json_type type = json_object_get_type(val);
						printf("Error:  key %s, type %d\n", key, type);

					}
				}
			}
		}

	}
	return 0;
}

/*******************************************************************/

void signal_handler(int signum)
{
    if ((signum == SIGINT) || (signum == SIGTERM))
    {
        g_shutdown_flag++;
    }
}

static void hello_cb(dsvdc_t *handle __attribute__((unused)),
		void *userdata)
{
    printf("Hello callback triggered, we are ready\n");
    bool *ready = (bool *)userdata;
    *ready = true;
}

static void ping_cb(dsvdc_t *handle __attribute__((unused)),
		const char *dsuid,
		void *userdata __attribute__((unused)))
{
    int ret;
    printf("received ping for dsuid %s\n", dsuid);
    if (strcmp(dsuid, g_vdc_dsuid) == 0) {
        ret = dsvdc_send_pong(handle, dsuid);
        printf("sent pong for vdc %s / return code %d\n", dsuid, ret);
        return;
    }
    netatmo_vdcd_t* dev;
	LL_FOREACH(devlist, dev) {
	    if (strcmp(dsuid, dev->dsuid) == 0)
	    {
	        ret = dsvdc_send_pong(handle, dev->dsuid);
	        printf("sent pong for device %s / return code %d\n", dsuid, ret);
	        return;
	    }
	}
}

static void announce_cb(dsvdc_t *handle __attribute__((unused)),
		int code, void *arg,
		void *userdata __attribute__((unused)))
{
    printf("announcement of device %s returned code: %d\n", (char *)arg, code);
}

static void bye_cb(dsvdc_t *handle __attribute__((unused)),
		const char *dsuid,
		void *userdata)
{
    printf("received bye for dsuid %s\n", dsuid);
    bool *ready = (bool *)userdata;
    *ready = false;
}

static void getprop_cb(dsvdc_t *handle,
		const char *dsuid,
		const char *name,
		uint32_t offset,
		uint32_t count,
		dsvdc_property_t *property,
		void *userdata __attribute__((unused)))
{
    printf("received get property callback for dsuid %s: \"%s\", offset/count %d/%d\n",
    		dsuid, name, offset, count);

    netatmo_vdcd_t* dev;
	LL_FOREACH(devlist, dev) {
	    if (strcmp(dsuid, dev->dsuid) == 0) {
	    	break;
	    }
	}
	if (dev == NULL) {
        fprintf(stderr, "GetProperty: unhandled dsuid %s\n", dsuid);
        dsvdc_property_free(property);
		return;
	}

    if (strcmp(name, "primaryGroup") == 0)
    {
        dsvdc_property_add_uint(property, 0, "primaryGroup", 3);
        dsvdc_send_property_response(handle, property);
    }
    else if (strcmp(name, "isMember") == 0)
    {
    	int n;
    	for (n = 0; n < 64; n++) {
    		switch (n) {
    		case 0:
    		case 3:
    		case 48:
        		dsvdc_property_add_bool(property, 0, "isMember", true);
        		break;
    		default:
        		dsvdc_property_add_bool(property, 0, "isMember", false);
        		break;
    		}
    	}
        dsvdc_send_property_response(handle, property);
    }
    else if (strcmp(name, "buttonInputDescriptions") == 0)
    {
        dsvdc_send_property_response(handle, property);
    }
    else if (strcmp(name, "buttonInputSettings") == 0)
    {
        dsvdc_send_property_response(handle, property);
    }
    else if (strcmp(name, "outputDescriptions") == 0)
    {
        dsvdc_send_property_response(handle, property);
    }
    else if (strcmp(name, "outputSettings") == 0)
    {
        dsvdc_send_property_response(handle, property);
    }
    else if (strcmp(name, "binaryInputDescriptions") == 0)
    {
        dsvdc_send_property_response(handle, property);
    }
    else if (strcmp(name, "binaryInputSettings") == 0)
    {
        dsvdc_send_property_response(handle, property);
    }
    else if (strcmp(name, "sensorDescriptions") == 0)
    {
    	int n, sensorUsage, sensorType;
    	char sensorName[64];

    	if (dev->mod->bid[0] == 2) {
    		sensorUsage = 2; // Outdoor
    	} else {
    		sensorUsage = 1; // Indoor
    	}

    	for (n = 0; n < dev->mod->values_num; n++) {
    		if (strcmp(dev->mod->values[n].data_type, "Temperature") == 0) {
    			sensorType = 1;
    		} else if (strcmp(dev->mod->values[n].data_type, "Humidity") == 0) {
    			sensorType = 2;
    		} else if (strcmp(dev->mod->values[n].data_type, "Co2") == 0) {
    			sensorType = 5;
    		} else if (strcmp(dev->mod->values[n].data_type, "Pressure") == 0) {
    			sensorType = 14;
    		} else if (strcmp(dev->mod->values[n].data_type, "Noise") == 0) {
    			sensorType = 15;
    		} else {
    			sensorType = 255;
    		}
    		snprintf(sensorName, 64, "%s-%s", dev->mod->name, dev->mod->values[n].data_type);
    		dsvdc_property_add_string(property, n, "name", sensorName);
    		dsvdc_property_add_uint(property, n, "sensorType", sensorType);
    		dsvdc_property_add_uint(property, n, "sensorUsage", sensorUsage);
    		dsvdc_property_add_double(property, n, "updateInterval", 60 * 5);

    		printf("  dsuid %s sensor %d: %s type %d usage %d\n", dsuid, n, sensorName, sensorType, sensorUsage);
    	}
        dsvdc_send_property_response(handle, property);
    }
    else if (strcmp(name, "name") == 0)
    {
        dsvdc_property_add_string(property, 0, "name", dev->mod->name);
        dsvdc_send_property_response(handle, property);
    }
    else
    {
        fprintf(stderr, "unhandled getProperty \"%s\"\n", name);
        dsvdc_property_free(property);
    }
}

int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
    struct sigaction action;

    bool ready = false;
    bool printed = false;

    memset(&action, 0, sizeof(action));
    action.sa_handler = signal_handler;
    action.sa_flags = 0;
    sigfillset(&action.sa_mask);

    if (sigaction(SIGINT, &action, NULL) < 0)
    {
        fprintf(stderr, "Could not register SIGINT handler!\n");
        return EXIT_FAILURE;
    }

    if (sigaction(SIGTERM, &action, NULL) < 0)
    {
        fprintf(stderr, "Could not register SIGTERM handler!\n");
        return EXIT_FAILURE;
    }

    curl_global_init(CURL_GLOBAL_ALL);

    memset(&netatmo, 0, sizeof(netatmo_data_t));
    if (read_config() < 0)
    {
        fprintf(stderr, "Could not read configuration data!\n");
    }

    /* initially synchronize NetAtmo device data */
    if (netatmo_get_devices() < 0)
    {
        fprintf(stderr, "Could not get device data from NetAtmo service!\n");
        return EXIT_FAILURE;
    }
    if (write_config() < 0)
    {
        fprintf(stderr, "Could not write configuration data!\n");
    }

    printf("dSVdc NetAtmo - press Ctrl-C to quit\n");

    /* initialize new library instance */
    dsvdc_t *handle = NULL;
    if (dsvdc_new(0, g_vdc_dsuid, "NetAtmo", &ready, &handle) != DSVDC_OK)
    {
        fprintf(stderr, "dsvdc_new() initialization failed\n");
        return EXIT_FAILURE;
    }

    /* setup callbacks */
    dsvdc_set_hello_callback(handle, hello_cb);
    dsvdc_set_ping_callback(handle, ping_cb);
    dsvdc_set_bye_callback(handle, bye_cb);
    dsvdc_set_get_property_callback(handle, getprop_cb);

    while(!g_shutdown_flag)
    {
        /* let the work function do our timing, 2secs timeout */
        dsvdc_work(handle, 2);

        {
        	static int queryDevicesTime = 0;
        	static int queryValuesTime = 0;
        	time_t now;

        	now = time(NULL);
        	if (g_access_token && (g_refresh_token_valid_until <= now)) {
        		free(g_access_token);
        		g_access_token = NULL;
        		netatmo_get_token();
        	}
        	if (queryDevicesTime <= now) {
        		if (netatmo_get_devices() >= 0) {
        			queryDevicesTime = g_resync_devices + now;
        		}
        	}
        	if (queryValuesTime <= now) {
        		if (netatmo_get_values() >= 0) {
        			queryValuesTime = g_refresh_values + now;
        		}
        	}
        }

        if (!dsvdc_is_connected(handle))
        {
            if (!printed)
            {
                fprintf(stderr, "vdC example: we are not connected!\n");
                printed = true;
            }
            ready = false;

            netatmo_vdcd_t* dev;
            LL_FOREACH(devlist, dev) {
            	dev->announced = false;
            }
        }
        else
        {
            printed = false;

            if (ready)
            {
            	int v;
                netatmo_vdcd_t* dev;

				LL_FOREACH(devlist, dev) {
            		if (dev->present && !dev->announced) {
                    	if (dsvdc_announce_device(handle, dev->dsuid, (void *)dev->dsuid, announce_cb) == DSVDC_OK)
                        {
                            dev->announced = true;
                        }
            		}
            		if (dev->present) {
        				dsvdc_property_t* prop;
            			for (v = 0; v < dev->mod->values_num; v++) {
            				if (dev->mod->values[v].last_reported < dev->mod->values[v].last_query) {
            					double val = dev->mod->values[v].value;

                				if (dsvdc_property_new("sensorStates", 1, &prop) < 0) {
                					continue;
                				}
            					dsvdc_property_add_double(prop, 0, "value", val);
                				dsvdc_push_property(handle, dev->dsuid, "sensorStates", v, prop);
                				dsvdc_property_free(prop);

                				dev->mod->values[v].last_reported = time(NULL);
            				}
            			}
            		}
            	}
            }
        }
    }

    dsvdc_cleanup(handle);

    curl_global_cleanup();
    return EXIT_SUCCESS;
}

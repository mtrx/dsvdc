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

#include <digitalSTROM/dsuid/dsuid.h>
#include <dsvdc/dsvdc.h>

#define MAX_MODULES 5
#define MAX_VALUES 5

typedef struct netatmo_value
{
  char *data_type;
  double value;
  double last_value;
  time_t last_query;
  time_t last_reported;
} netatmo_value_t;

typedef struct netatmo_module
{
  dsuid_t dsuid;
  char *id;
  char *name;
  char *type;
  time_t last_message;
  time_t last_seen;
  int values_num;
  netatmo_value_t values[MAX_VALUES];
  int battery_vp;
  unsigned char bid_length;
  unsigned char bid[16];
} netatmo_module_t;

typedef struct netatmo_base
{
  char *station_name;
  char *bssid;
  double location_x;
  double location_y;
  double location_alt;
  int modules_num;
  netatmo_module_t modules[MAX_MODULES];
} netatmo_base_t;

typedef struct netatmo_data
{
  char *dsuid;
  char *username;
  char *password;
  char *authcode;
  netatmo_base_t base;
} netatmo_data_t;

typedef struct netatmo_vdcd
{
  struct netatmo_vdcd* next;
  dsuid_t dsuid;
  char dsuidstring[36];
  char *id;
  int announced;
  int present;
  netatmo_module_t* mod;
} netatmo_vdcd_t;

static netatmo_data_t netatmo;
static netatmo_vdcd_t* devlist = NULL;

struct memory_struct
{
  char *memory;
  size_t size;
};

struct data
{
  char trace_ascii; /* 1 or 0 */
};

#define NETATMO_OUT_OF_MEMORY -1
#define NETATMO_AUTH_FAILED -10
#define NETATMO_BAD_CONFIG -12
#define NETATMO_DEVLIST_FAILED -13
#define NETATMO_GETMEASURE_FAILED -13
#define NETATMO_BAD_ACCESS_TOKEN -14

static const char *g_cfgfile = "netatmo.cfg";
static const char *g_client_id = "52823f931877590c917b23f7";
static const char *g_client_secret = NULL;
static char *g_access_token = NULL;
static char *g_refresh_token = NULL;
static time_t g_refresh_token_valid_until = 0;
static time_t g_resync_devices = 60 * 60;
static time_t g_refresh_values = 5 * 60;
static char g_vdc_dsuid[35] =
  { 0, };
static char g_lib_dsuid[35] =
  { "053f848b85bb382198025cea1fd087f100" };
static int g_shutdown_flag = 0;
static int g_debug_flag = 0;

static const uint8_t deviceIcon16_png[] =
  { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x10, 0x08, 0x03, 0x00, 0x00, 0x00, 0x28, 0x2D, 0x0F, 0x53, 0x00, 0x00, 0x01, 0x41, 0x50,
    0x4C, 0x54, 0x45, 0x4C, 0x89, 0x93, 0x4E, 0x8A, 0x94, 0x56, 0x90, 0x98, 0x59, 0x92, 0x9A, 0x5C, 0x93, 0x9C, 0x5C,
    0x94, 0x9C, 0x60, 0x96, 0x9F, 0x66, 0x9A, 0xA2, 0x68, 0x9B, 0xA3, 0x6A, 0x9C, 0xA4, 0x6A, 0x9D, 0xA4, 0x6A, 0x9D,
    0xA5, 0x6C, 0x9E, 0xA6, 0x6E, 0x9F, 0xA7, 0x74, 0xA4, 0xAB, 0x76, 0xA4, 0xAC, 0x79, 0xA7, 0xAE, 0x7A, 0xA7, 0xAF,
    0x7B, 0xA7, 0xAF, 0x7B, 0xA8, 0xAF, 0x7C, 0xA8, 0xAF, 0x7E, 0xAA, 0xB0, 0x7F, 0xAB, 0xB2, 0x82, 0xAC, 0xB3, 0x83,
    0xAD, 0xB4, 0x84, 0xAE, 0xB5, 0x86, 0xAF, 0xB6, 0x89, 0xB1, 0xB7, 0x8A, 0xB2, 0xB8, 0x8E, 0xB4, 0xBA, 0x90, 0xB6,
    0xBB, 0x95, 0xB9, 0xBF, 0x96, 0xB9, 0xBF, 0x9C, 0xBE, 0xC3, 0x9F, 0xBF, 0xC3, 0xA0, 0xC0, 0xC5, 0xA1, 0xC1, 0xC6,
    0xA2, 0xC2, 0xC6, 0xA3, 0xC2, 0xC7, 0xA5, 0xC4, 0xC8, 0xA6, 0xC4, 0xC9, 0xA7, 0xC4, 0xC9, 0xA6, 0xC5, 0xC9, 0xA8,
    0xC6, 0xCA, 0xA9, 0xC6, 0xCA, 0xAB, 0xC7, 0xCC, 0xAC, 0xC8, 0xCC, 0xB1, 0xCB, 0xCF, 0xB4, 0xCD, 0xD1, 0xB5, 0xCF,
    0xD2, 0xB7, 0xCF, 0xD2, 0xB7, 0xCF, 0xD3, 0xB8, 0xD0, 0xD3, 0xB9, 0xD1, 0xD4, 0xBA, 0xD2, 0xD5, 0xBB, 0xD2, 0xD6,
    0xBD, 0xD4, 0xD7, 0xC0, 0xD5, 0xD9, 0xC0, 0xD6, 0xD9, 0xC1, 0xD6, 0xD9, 0xC3, 0xD7, 0xDB, 0xC5, 0xD9, 0xDC, 0xC7,
    0xDA, 0xDD, 0xC8, 0xDA, 0xDD, 0xC8, 0xDB, 0xDD, 0xCC, 0xDD, 0xDF, 0xCC, 0xDD, 0xE0, 0xCE, 0xDE, 0xE1, 0xCF, 0xDF,
    0xE1, 0xD0, 0xE0, 0xE2, 0xD3, 0xE2, 0xE4, 0xD5, 0xE3, 0xE5, 0xD7, 0xE5, 0xE6, 0xDA, 0xE6, 0xE8, 0xDD, 0xE8, 0xEA,
    0xDE, 0xE9, 0xEB, 0xDF, 0xEA, 0xEB, 0xE0, 0xEA, 0xEC, 0xDF, 0xEB, 0xEC, 0xE0, 0xEB, 0xEC, 0xE1, 0xEB, 0xED, 0xE2,
    0xEC, 0xED, 0xE3, 0xED, 0xEE, 0xE5, 0xEE, 0xEF, 0xE6, 0xEF, 0xF0, 0xE8, 0xF0, 0xF1, 0xEA, 0xF1, 0xF2, 0xEA, 0xF1,
    0xF3, 0xEB, 0xF1, 0xF2, 0xEB, 0xF2, 0xF2, 0xEB, 0xF2, 0xF3, 0xED, 0xF3, 0xF4, 0xEF, 0xF4, 0xF5, 0xEF, 0xF5, 0xF5,
    0xF0, 0xF5, 0xF6, 0xF1, 0xF6, 0xF7, 0xF3, 0xF7, 0xF8, 0xF5, 0xF8, 0xF9, 0xF7, 0xFA, 0xFA, 0xF8, 0xFA, 0xFB, 0xFA,
    0xFB, 0xFC, 0xFB, 0xFC, 0xFC, 0xFB, 0xFC, 0xFD, 0xFC, 0xFD, 0xFD, 0xFD, 0xFE, 0xFE, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xF0, 0xCE, 0xC3, 0x37, 0x00, 0x00, 0x00, 0x09, 0x70, 0x48, 0x59, 0x73, 0x00, 0x00, 0x16, 0x25, 0x00, 0x00,
    0x16, 0x25, 0x01, 0x49, 0x52, 0x24, 0xF0, 0x00, 0x00, 0x00, 0x07, 0x74, 0x49, 0x4D, 0x45, 0x07, 0xDE, 0x08, 0x1B,
    0x0E, 0x0A, 0x14, 0xB9, 0x23, 0x5D, 0x5D, 0x00, 0x00, 0x01, 0x1B, 0x49, 0x44, 0x41, 0x54, 0x18, 0x19, 0x01, 0x10,
    0x01, 0xEF, 0xFE, 0x00, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A,
    0x6A, 0x00, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x00,
    0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x00, 0x6A, 0x6A,
    0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x68, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x00, 0x6A, 0x6A, 0x6A, 0x6A,
    0x6A, 0x6A, 0x6A, 0x6A, 0x01, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x00, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A,
    0x6A, 0x6A, 0x01, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x00, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A,
    0x01, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x00, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x01, 0x6A,
    0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x00, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x28, 0x6A, 0x6A, 0x6A,
    0x6A, 0x6A, 0x6A, 0x6A, 0x00, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A,
    0x6A, 0x6A, 0x00, 0x6A, 0x6A, 0x3B, 0x6A, 0x3F, 0x43, 0x6A, 0x2C, 0x4C, 0x3A, 0x47, 0x6A, 0x4E, 0x5C, 0x4B, 0x6A,
    0x00, 0x6A, 0x6A, 0x6A, 0x42, 0x6A, 0x64, 0x6A, 0x45, 0x6A, 0x6A, 0x4F, 0x20, 0x11, 0x12, 0x26, 0x6A, 0x00, 0x6A,
    0x6A, 0x6A, 0x58, 0x6A, 0x64, 0x23, 0x67, 0x6A, 0x6A, 0x4F, 0x1F, 0x11, 0x05, 0x18, 0x6A, 0x00, 0x6A, 0x6A, 0x6A,
    0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x00, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A,
    0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x00, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A,
    0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0x6A, 0xB0, 0x2F, 0x63, 0x1B, 0xA2, 0xC7, 0x63, 0xB3, 0x00, 0x00,
    0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82 };

/*******************************************************************/

int
read_config()
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
    fprintf(stderr, "Error in configuration: l.%d %s\n", config_error_line(&config), config_error_text(&config));
    config_destroy(&config);
    return -1;
  }

  if (config_lookup_string(&config, "vdcdsuid", (const char **) &sval))
    strncpy(g_vdc_dsuid, sval, sizeof(g_vdc_dsuid));
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
  config_lookup_int(&config, "debug", (int *) &g_debug_flag);

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

  if (g_cfgfile != NULL) {
    config_destroy(&config);
  }

  // cleanup old list
  devlist = NULL;

  netatmo_vdcd_t* dev;
  for (n = 0; n < MAX_MODULES; n++) {
    netatmo_module_t* m = &netatmo.base.modules[n];

    if (m->id) {
      char buffer[128];
      strcpy(buffer, netatmo.base.bssid);
      strcat(buffer, "-");
      strcat(buffer, m->id);

      int found = 0;
      LL_FOREACH(devlist, dev)
      {
        if (m->id && (strcasecmp(buffer, dev->id) == 0)) {
          found = 1;
          break;
        }
      }
      if (found == 0) {
        dev = malloc(sizeof(netatmo_vdcd_t));
        if (!dev) {
          return NETATMO_OUT_OF_MEMORY;
        }
        memset(dev, 0, sizeof(netatmo_vdcd_t));
      }

      dev->id = strdup(buffer);
      dev->present = false;
      dev->announced = false;
      dev->mod = m;

      dsuid_generate_v3_from_namespace(DSUID_NS_IEEE_MAC, buffer, &dev->dsuid);
      dsuid_to_string(&dev->dsuid, dev->dsuidstring);

      if (!found) {
        LL_APPEND(devlist, dev);
      }
    }
  }

  return 0;
}

int
write_config()
{
  config_t config;
  config_setting_t* cfg_root;
  config_setting_t* setting;
  config_setting_t* devicesetting;
  config_setting_t* modulesetting;
  int n, v;

  config_init(&config);
  cfg_root = config_root_setting(&config);

  setting = config_setting_add(cfg_root, "vdcdsuid", CONFIG_TYPE_STRING);
  if (setting == NULL) {
    setting = config_setting_get_member(cfg_root, "vdcdsuid");
  }
  config_setting_set_string(setting, g_vdc_dsuid);

  setting = config_setting_add(cfg_root, "secret", CONFIG_TYPE_STRING);
  if (setting == NULL) {
    setting = config_setting_get_member(cfg_root, "secret");
  }
  config_setting_set_string(setting, g_client_secret);

  setting = config_setting_add(cfg_root, "username", CONFIG_TYPE_STRING);
  if (setting == NULL) {
    setting = config_setting_get_member(cfg_root, "username");
  }
  config_setting_set_string(setting, netatmo.username);

  setting = config_setting_add(cfg_root, "password", CONFIG_TYPE_STRING);
  if (setting == NULL) {
    setting = config_setting_get_member(cfg_root, "password");
  }
  config_setting_set_string(setting, netatmo.password);

  setting = config_setting_add(cfg_root, "authcode", CONFIG_TYPE_STRING);
  if (setting == NULL) {
    setting = config_setting_get_member(cfg_root, "authcode");
  }
  config_setting_set_string(setting, netatmo.authcode);

  devicesetting = config_setting_add(cfg_root, "device", CONFIG_TYPE_GROUP);

  setting = config_setting_add(devicesetting, "bssid", CONFIG_TYPE_STRING);
  if (setting == NULL) {
    setting = config_setting_get_member(devicesetting, "bssid");
  }
  config_setting_set_string(setting, netatmo.base.bssid);

  setting = config_setting_add(devicesetting, "station_name", CONFIG_TYPE_STRING);
  if (setting == NULL) {
    setting = config_setting_get_member(devicesetting, "station_name");
  }
  config_setting_set_string(setting, netatmo.base.station_name);

  setting = config_setting_add(devicesetting, "location_x", CONFIG_TYPE_FLOAT);
  if (setting == NULL) {
    setting = config_setting_get_member(devicesetting, "location_x");
  }
  config_setting_set_float(setting, netatmo.base.location_x);

  setting = config_setting_add(devicesetting, "location_y", CONFIG_TYPE_FLOAT);
  if (setting == NULL) {
    setting = config_setting_get_member(devicesetting, "location_y");
  }
  config_setting_set_float(setting, netatmo.base.location_y);

  setting = config_setting_add(devicesetting, "location_alt", CONFIG_TYPE_FLOAT);
  if (setting == NULL) {
    setting = config_setting_get_member(devicesetting, "location_alt");
  }
  config_setting_set_float(setting, netatmo.base.location_alt);

  setting = config_setting_add(devicesetting, "modules", CONFIG_TYPE_INT);
  if (setting == NULL) {
    setting = config_setting_get_member(devicesetting, "modules");
  }
  config_setting_set_int(setting, netatmo.base.modules_num);

  modulesetting = config_setting_add(cfg_root, "module", CONFIG_TYPE_GROUP);

  for (n = 0; n < netatmo.base.modules_num; n++) {
    char path[128];
    netatmo_module_t* module = &netatmo.base.modules[n];

    sprintf(path, "m%d", n);
    config_setting_t *s = config_setting_add(modulesetting, path, CONFIG_TYPE_GROUP);
    if (s == NULL) {
      s = config_setting_get_member(modulesetting, path);
    }

    setting = config_setting_add(s, "name", CONFIG_TYPE_STRING);
    if (setting == NULL) {
      setting = config_setting_get_member(s, "name");
    }
    config_setting_set_string(setting, module->name);

    setting = config_setting_add(s, "id", CONFIG_TYPE_STRING);
    if (setting == NULL) {
      setting = config_setting_get_member(s, "id");
    }
    config_setting_set_string(setting, module->id);

    setting = config_setting_add(s, "last_message", CONFIG_TYPE_INT);
    if (setting == NULL) {
      setting = config_setting_get_member(s, "last_message");
    }
    config_setting_set_int(setting, module->last_message);

    setting = config_setting_add(s, "last_seen", CONFIG_TYPE_INT);
    if (setting == NULL) {
      setting = config_setting_get_member(s, "last_seen");
    }
    config_setting_set_int(setting, module->last_seen);

    setting = config_setting_add(s, "values", CONFIG_TYPE_INT);
    if (setting == NULL) {
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
      if (setting == NULL) {
        setting = config_setting_get_member(v, "data_type");
      }
      config_setting_set_string(setting, value->data_type);

      setting = config_setting_add(v, "last_reported", CONFIG_TYPE_INT);
      if (setting == NULL) {
        setting = config_setting_get_member(v, "last_reported");
      }
      config_setting_set_int(setting, value->last_reported);

      setting = config_setting_add(v, "last_value", CONFIG_TYPE_FLOAT);
      if (setting == NULL) {
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

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct memory_struct *mem = (struct memory_struct *) userp;

  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if (mem->memory == NULL) {
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
  return realsize;
}

static void
DebugDump(const char *text, FILE *stream, unsigned char *ptr, size_t size, char nohex)
{
  size_t i;
  size_t c;

  unsigned int width = 0x10;

  if (nohex)
    /* without the hex output, we can fit more on screen */
    width = 0x40;

  fprintf(stream, "%s, %10.10ld bytes (0x%8.8lx)\n", text, (long) size, (long) size);

  for (i = 0; i < size; i += width) {

    fprintf(stream, "%4.4lx: ", (long) i);

    if (!nohex) {
      /* hex not disabled, show it */
      for (c = 0; c < width; c++)
        if (i + c < size)
          fprintf(stream, "%02x ", ptr[i + c]);
        else
          fputs("   ", stream);
    }

    for (c = 0; (c < width) && (i + c < size); c++) {
      /* check for 0D0A; if found, skip past and start a new line of output */
      if (nohex && (i + c + 1 < size) && ptr[i + c] == 0x0D && ptr[i + c + 1] == 0x0A) {
        i += (c + 2 - width);
        break;
      }
      fprintf(stream, "%c", (ptr[i + c] >= 0x20) && (ptr[i + c] < 0x80) ? ptr[i + c] : '.');
      /* check again for 0D0A, to avoid an extra \n if it's at width */
      if (nohex && (i + c + 2 < size) && ptr[i + c + 1] == 0x0D && ptr[i + c + 2] == 0x0A) {
        i += (c + 3 - width);
        break;
      }
    }
    fputc('\n', stream); /* newline */
  }
  fflush(stream);
}

static int
DebugCallback(CURL *handle, curl_infotype type, char *data, size_t size, void *userp)
{

  struct data *config = (struct data *) userp;
  const char *text;
  (void) handle; /* prevent compiler warning */

  switch (type) {
    case CURLINFO_TEXT:
      fprintf(stderr, "== Info: %s", data);
    default: /* in case a new one is introduced to shock us */
      return 0;

    case CURLINFO_HEADER_OUT:
      text = "=> Send header";
      break;
    case CURLINFO_DATA_OUT:
      text = "=> Send data";
      break;
    case CURLINFO_SSL_DATA_OUT:
      text = "=> Send SSL data";
      break;
    case CURLINFO_HEADER_IN:
      text = "<= Recv header";
      break;
    case CURLINFO_DATA_IN:
      text = "<= Recv data";
      break;
    case CURLINFO_SSL_DATA_IN:
      text = "<= Recv SSL data";
      break;
  }
  DebugDump(text, stderr, (unsigned char *) data, size, config->trace_ascii);
  return 0;
}

struct memory_struct*
query(const char *url, const char *postthis)
{
  CURL *curl;
  CURLcode res;
  struct memory_struct *chunk;

  chunk = malloc(sizeof(struct memory_struct));
  if (chunk == NULL) {
    printf("not enough memory\n");
    return NULL;
  }
  chunk->memory = malloc(1);
  chunk->size = 0;

  curl = curl_easy_init();
  if (curl == NULL) {
    printf("curl init failure\n");
    free(chunk->memory);
    free(chunk);
    return NULL;
  }
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void * )chunk);
  curl_easy_setopt(curl, CURLOPT_POST, 1);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postthis);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long )strlen(postthis));

  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded;charset=UTF-8");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  if (g_debug_flag) {
    struct data config;
    config.trace_ascii = 1; /* enable ascii tracing */

    curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, DebugCallback);
    curl_easy_setopt(curl, CURLOPT_DEBUGDATA, &config);
    /* the DEBUGFUNCTION has no effect until we enable VERBOSE */
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  }

  res = curl_easy_perform(curl);
  if (res != CURLE_OK) {
    fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
  }
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

  if (res != CURLE_OK) {
    free(chunk->memory);
    free(chunk);
    return NULL;
  }
  return chunk;
}

/*******************************************************************/

int
netatmo_get_token()
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
    if (response == NULL) {
      printf("NetAtmo authcode failure");
      return NETATMO_AUTH_FAILED;
    }

    // invalidate refresh token
    free(g_refresh_token);
    g_refresh_token = NULL;
  } else if (netatmo.authcode && strlen(netatmo.authcode) > 0) {
    char request_body[1024];
    strcpy(request_body, "grant_type=authorization_code");
    strcat(request_body, "&client_id=");
    strcat(request_body, g_client_id);
    strcat(request_body, "&client_secret=");
    strcat(request_body, g_client_secret);
    strcat(request_body, "&code=");
    strcat(request_body, netatmo.authcode);

    printf("Get access token with auth code\n");
    response = query("https://api.netatmo.net/oauth2/token", request_body);
    if (response == NULL) {
      printf("NetAtmo authcode failure");
      return NETATMO_AUTH_FAILED;
    }
  } else if (netatmo.username && netatmo.password) {
    char request_body[1024];
    strcpy(request_body, "grant_type=password");
    strcat(request_body, "&client_id=");
    strcat(request_body, g_client_id);
    strcat(request_body, "&client_secret=");
    strcat(request_body, g_client_secret);
    strcat(request_body, "&username=");
    strcat(request_body, netatmo.username);
    strcat(request_body, "&password=");
    strcat(request_body, netatmo.password);
    strcat(request_body, "&scope=read_station");

    printf("Get access token with username and password\n");
    response = query("https://api.netatmo.net/oauth2/token", request_body);
    if (response == NULL) {
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
        if (g_access_token)
          free(g_access_token);
        g_access_token = strdup(json_object_get_string(val));
      }
    } else if (!strcmp(key, "refresh_token")) {
      if (type == json_type_string) {
        if (g_refresh_token)
          free(g_refresh_token);
        g_refresh_token = strdup(json_object_get_string(val));
      }
    } else if (!strcmp(key, "expires_in")) {
      if (type == json_type_int) {
        int exp = json_object_get_int(val);
        g_refresh_token_valid_until = time(NULL) + exp - 120; // 2 minutes before expiration
      }
    } else if (!strcmp(key, "error")) {
      if (type == json_type_string) {
        printf("NetAtmo returned error: %s\n", json_object_get_string(val));
      }
    } else {
      printf("Unknown key: %s\n", key);
    }
  }

  free(response->memory);
  free(response);
  return 0;
}

int
netatmo_get_devices()
{
  int rc, n, nd, v;

  printf("Reading device list from NetAtmo\n");

  if (!g_access_token) {
    if ((rc = netatmo_get_token()) != 0) {
      return rc;
    }
    if (!g_access_token) {
      return NETATMO_BAD_ACCESS_TOKEN;
    }
  }

  char request_body[1024];
  strcpy(request_body, "access_token=");
  strcat(request_body, g_access_token);

  struct memory_struct *response = query("https://api.netatmo.net/api/devicelist", request_body);
  if (response == NULL) {
    printf("NetAtmo getting device list failed");
    return NETATMO_DEVLIST_FAILED;
  }

  for (n = 0; n < MAX_MODULES; n++) {
    netatmo_module_t* nmodule = &netatmo.base.modules[n];
    if (nmodule->id)
      free(nmodule->id);
    if (nmodule->name)
      free(nmodule->name);
    for (v = 0; v < MAX_VALUES; v++) {
      if (nmodule->values[v].data_type)
        free(nmodule->values[v].data_type);
    }
  }
  memset(netatmo.base.modules, 0, sizeof(netatmo_module_t) * MAX_MODULES);

  printf("\n*** DEVICE Query:\n%s\n", response->memory);

  json_object *jobj = json_tokener_parse(response->memory);
  if (jobj == NULL) {
    printf("NetAtmo returned unparsable json response");
    return NETATMO_GETMEASURE_FAILED;
  }

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
        json_object_object_foreach(jobj2, key, val)
        {
          enum json_type type = val ? json_object_get_type(val) : -1;
          //printf("  key %s, type %d\n", key, type);

          if (!strcmp(key, "devices")) {
            if (type == json_type_array) {
              //array_list* dev = json_object_get_array(val);
              netatmo_module_t* nmodule = &netatmo.base.modules[0];

              for (n = 0; n < 1 /*dev->length*/; n++) {
                json_object* jobj3 = json_object_array_get_idx(val, n);
                json_object_object_foreach(jobj3, key, val)
                {
                  enum json_type type = val ? json_object_get_type(val) : -1;
                  //printf("    key %s, type %d\n", key, type);

                  if (!strcmp(key, "_id") && (type == json_type_string)) {
                    nmodule->id = strdup(json_object_get_string(val));
                  } else if (!strcmp(key, "type") && (type == json_type_string)) {
                    nmodule->type = strdup(json_object_get_string(val));
                  } else if (!strcmp(key, "last_message") && (type == json_type_int)) {
                    nmodule->last_message = json_object_get_int(val);
                  } else if (!strcmp(key, "last_seen") && (type == json_type_int)) {
                    nmodule->last_seen = json_object_get_int(val);
                  } else if (!strcmp(key, "place") && (type == json_type_object)) {
                    json_object *jobj4 = val;
                    json_object_object_foreach(jobj4, key, val)
                    {
                      enum json_type type = val ? json_object_get_type(val) : -1;
                      //printf("    key %s, type %d\n", key, type);

                      if (!strcmp(key, "altitude") && type == json_type_string) {
                        netatmo.base.location_alt = json_object_get_int(val);
                      } else if (!strcmp(key, "bssid") && type == json_type_string) {
                        if (netatmo.base.bssid)
                          free(netatmo.base.bssid);
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
                      if (netatmo.base.station_name)
                        free(netatmo.base.station_name);
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

              netatmo.base.modules_num = mod->length + 1 > MAX_MODULES ? MAX_MODULES : mod->length + 1;

              for (n = 0; n < mod->length; n++) {
                netatmo_module_t* nmodule = &netatmo.base.modules[1 + n];

                json_object* jobj3 = json_object_array_get_idx(val, n);
                json_object_object_foreach(jobj3, key, val)
                {
                  enum json_type type = val ? json_object_get_type(val) : -1;
                  //printf("    key %s, type %d\n", key, type);

                  if (!strcmp(key, "module_name") && (type == json_type_string)) {
                    nmodule->name = strdup(json_object_get_string(val));
                  } else if (!strcmp(key, "_id") && (type == json_type_string)) {
                    nmodule->id = strdup(json_object_get_string(val));
                  } else if (!strcmp(key, "type") && (type == json_type_string)) {
                    nmodule->type = strdup(json_object_get_string(val));
                  } else if (!strcmp(key, "last_message") && (type == json_type_string)) {
                    nmodule->last_message = json_object_get_int(val);
                  } else if (!strcmp(key, "last_seen") && (type == json_type_string)) {
                    nmodule->last_seen = json_object_get_int(val);
                  } else if (!strcmp(key, "battery_vp") && (type == json_type_string)) {
                    nmodule->battery_vp = json_object_get_int(val);
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

  if (NULL == netatmo.base.bssid) {
    netatmo.base.bssid = strdup(netatmo.base.modules[0].id);
  }

  netatmo_vdcd_t* dev;
  for (n = 0; n < MAX_MODULES; n++) {
    netatmo_module_t* m = &netatmo.base.modules[n];

    if (m->id) {
      unsigned char *mac = m->bid;
      m->bid_length = 6;
      sscanf(m->id, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

      char buffer[128] =
        { 0, };
      strncpy(buffer, netatmo.base.bssid, 64);
      strcat(buffer, "-");
      strcat(buffer, m->id);

      int found = 0;
      LL_FOREACH(devlist, dev)
      {
        if (!strcmp(buffer, dev->id)) {
          found = 1;
          break;
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

      dev->id = strdup(buffer);
      dev->mod = m;

      dsuid_generate_v3_from_namespace(DSUID_NS_IEEE_MAC, buffer, &dev->dsuid);
      dsuid_to_string(&dev->dsuid, dev->dsuidstring);

      printf("%s module: ID %s - DSUID %s\n", found ? "Existing" : "New", dev->id, dev->dsuidstring);
    }
  }

  free(response->memory);
  free(response);
  return 0;
}

int
netatmo_get_values()
{
  int rc, n, v;
  time_t now;

  printf("Reading data values from NetAtmo\n");

  if (!g_access_token) {
    if ((rc = netatmo_get_token()) != 0) {
      return rc;
    }
  }

  for (n = 0; n < netatmo.base.modules_num; n++) {
    netatmo_module_t* m = &netatmo.base.modules[n];

    char request_body[1024];
    char request_type[128];

    if (NULL == netatmo.base.modules[n].type) {
      strcpy(request_type, "Temperature");
    } else if (strcmp(netatmo.base.modules[n].type, "NAModule1") == 0) {
      strcpy(request_type, "Temperature,Humidity");
    } else if (strcmp(netatmo.base.modules[n].type, "NAModule4") == 0) {
      strcpy(request_type, "Temperature,Humidity,Co2");
    } else if (strcmp(netatmo.base.modules[n].type, "NAMain") == 0) {
      strcpy(request_type, "Temperature,Humidity,Co2,Noise,Pressure");
    } else {
      strcpy(request_type, "Temperature");
    }

    strcpy(request_body, "access_token=");
    strcat(request_body, g_access_token);
    strcat(request_body, "&device_id=");
    strcat(request_body, netatmo.base.modules[0].id);
    strcat(request_body, "&module_id=");
    strcat(request_body, m->id);
    strcat(request_body, "&scale=max&type=");
    strcat(request_body, request_type);
    strcat(request_body, "&date_end=last");

    struct memory_struct *response = query("https://api.netatmo.net/api/getmeasure", request_body);
    if (response == NULL) {
      printf("NetAtmo getting measurement failed");
      return NETATMO_GETMEASURE_FAILED;
    }
    now = time(NULL);

    printf("\n*** VALUE Query:\n%s\n", response->memory);

    json_object *jobj = json_tokener_parse(response->memory);
    if (jobj == NULL) {
      printf("NetAtmo returned unparsable json response");
      return NETATMO_GETMEASURE_FAILED;
    }

    json_object_object_foreach(jobj, key, val)
    {
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
          json_object_object_foreach(jobj2, key, val)
          {
            enum json_type type = json_object_get_type(val);
            //printf(" -> key %s, type %d\n", key, type);

            if (!strcmp(key, "beg_time") && (type == json_type_int)) {
              now = json_object_get_int(val);

            } else if (!strcmp(key, "value") && (type == json_type_array)) {
              json_object* jobj3 = json_object_array_get_idx(val, 0);
              enum json_type type = json_object_get_type(jobj3);
              if (type == json_type_array) {
                array_list* va = json_object_get_array(jobj3);
                json_object* jobj_t = va->length >= 1 ? json_object_array_get_idx(jobj3, 0) : NULL;
                json_object* jobj_h = va->length >= 2 ? json_object_array_get_idx(jobj3, 1) : NULL;
                json_object* jobj_c = va->length >= 3 ? json_object_array_get_idx(jobj3, 2) : NULL;
                json_object* jobj_noise = va->length >= 4 ? json_object_array_get_idx(jobj3, 3) : NULL;
                json_object* jobj_pressure = va->length >= 5 ? json_object_array_get_idx(jobj3, 4) : NULL;
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
                  if (strcmp(netatmo.base.modules[n].values[v].data_type, "Co2") == 0) {
                    netatmo.base.modules[n].values[v].last_value = netatmo.base.modules[n].values[v].value;
                    netatmo.base.modules[n].values[v].value = json_object_get_double(jobj_c);
                    netatmo.base.modules[n].values[v].last_query = now;
                  }
                  if (strcmp(netatmo.base.modules[n].values[v].data_type, "Noise") == 0) {
                    netatmo.base.modules[n].values[v].last_value = netatmo.base.modules[n].values[v].value;
                    netatmo.base.modules[n].values[v].value = json_object_get_double(jobj_noise);
                    netatmo.base.modules[n].values[v].last_query = now;
                  }
                  if (strcmp(netatmo.base.modules[n].values[v].data_type, "Pressure") == 0) {
                    netatmo.base.modules[n].values[v].last_value = netatmo.base.modules[n].values[v].value;
                    netatmo.base.modules[n].values[v].value = json_object_get_double(jobj_pressure);
                    netatmo.base.modules[n].values[v].last_query = now;
                  }
                }
              }
            }
          }
        }

      } else if (!strcmp(key, "error")) {
        if (type == json_type_object) {
          json_object *jobj2 = val;
          json_object_object_foreach(jobj2, key, val)
          {
            enum json_type type = json_object_get_type(val);
            printf("Error:  key %s, type %d\n", key, type);

          }
        }
      }
    }

  }

  netatmo_vdcd_t* dev;
  now = time(NULL);
  LL_FOREACH(devlist, dev)
  {
    for (v = 0; v < dev->mod->values_num; v++) {
      // value too old (> 4h) ?
      if (now >= dev->mod->values[v].last_query + 2400) {
        if (dev->present)
          printf("%s module: ID %s - DSUID is INACTIVE\n", dev->id, dev->dsuidstring);
        dev->present = false;
      } else {
        if (!dev->present)
          printf("%s module: ID %s - DSUID is ACTIVE\n", dev->id, dev->dsuidstring);
        dev->present = true;
      }
    }
  }

  return 0;
}

/*******************************************************************/

void
signal_handler(int signum)
{
  if ((signum == SIGINT) || (signum == SIGTERM)) {
    g_shutdown_flag++;
  }
}

static void
hello_cb(dsvdc_t *handle __attribute__((unused)), void *userdata)
{
  printf("Hello callback triggered, we are ready\n");
  bool *ready = (bool *) userdata;
  *ready = true;
}

static void
ping_cb(dsvdc_t *handle __attribute__((unused)), const char *dsuid, void *userdata __attribute__((unused)))
{
  int ret;
  printf("received ping for dsuid %s\n", dsuid);
  if (strcasecmp(dsuid, g_vdc_dsuid) == 0) {
    ret = dsvdc_send_pong(handle, dsuid);
    printf("sent pong for vdc %s / return code %d\n", dsuid, ret);
    return;
  }
  netatmo_vdcd_t* dev;
  LL_FOREACH(devlist, dev)
  {
    if (strcasecmp(dsuid, dev->dsuidstring) == 0) {
      ret = dsvdc_send_pong(handle, dev->dsuidstring);
      printf("sent pong for device %s / return code %d\n", dsuid, ret);
      return;
    }
  }
}

static void
announce_device_cb(dsvdc_t *handle __attribute__((unused)), int code, void *arg, void *userdata __attribute__((unused)))
{
  printf("announcement of device %s returned code: %d\n", (char *) arg, code);
}

static void
announce_container_cb(dsvdc_t *handle __attribute__((unused)), int code, void *arg,
    void *userdata __attribute__((unused)))
{
  printf("announcement of container %s returned code: %d\n", (char *) arg, code);
}

static void
bye_cb(dsvdc_t *handle __attribute__((unused)), const char *dsuid, void *userdata)
{
  printf("received bye for dsuid %s\n", dsuid);
  *(bool *) userdata = false;
}

static void
getprop_cb(dsvdc_t *handle, const char *dsuid, dsvdc_property_t *property, const dsvdc_property_t *query,
    void *userdata)
{
  (void) userdata;
  int ret;
  size_t i;
  char *name;
  netatmo_vdcd_t* dev;

  printf("\n** get property for dsuid: %s\n", dsuid);

  /*
   * Properties for the VDC
   */
  if (strcasecmp(g_vdc_dsuid, dsuid) == 0) {
    for (i = 0; i < dsvdc_property_get_num_properties(query); i++) {

      int ret = dsvdc_property_get_name(query, i, &name);
      if (ret != DSVDC_OK) {
        fprintf(stderr, "getprop_cb: error getting property name, abort\n");
        dsvdc_send_property_response(handle, property);
        return;
      }
      if (!name) {
        fprintf(stderr, "getprop_cb: not yet handling wildcard properties\n");
        dsvdc_send_property_response(handle, property);
        return;
      }
      printf("**** request name: %s\n", name);

      if (strcmp(name, "hardwareGuid") == 0) {
        char info[256];
        char buffer[32];
        size_t n;

        strcpy(info, "macaddress:");
        sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x", netatmo.base.bssid[5], netatmo.base.bssid[4],
            netatmo.base.bssid[3], netatmo.base.bssid[2], netatmo.base.bssid[1], netatmo.base.bssid[0]);
        strcat(info, buffer);
        dsvdc_property_add_string(property, name, info);

      } else if (strcmp(name, "modelGuid") == 0) {
        dsvdc_property_add_string(property, name, "NetAtmo VDC Prototype by mtr [modelGuid]");

      } else if (strcmp(name, "vendorId") == 0) {
        dsvdc_property_add_string(property, name, "michael@tross.org");

      } else if (strcmp(name, "name") == 0) {
        dsvdc_property_add_string(property, name, "NetAtmo VDC");

      } else if (strcmp(name, "model") == 0) {
        dsvdc_property_add_string(property, name, "NetAtmo VDC Prototype by mtr [model]");

      } else if (strcmp(name, "capabilities") == 0) {
        dsvdc_property_t *reply;
        ret = dsvdc_property_new(&reply);
        if (ret != DSVDC_OK) {
          printf("failed to allocate reply property for %s\n", name);
          free(name);
          continue;
        }
        dsvdc_property_add_bool(reply, "metering", false);

      } else if (strcmp(name, "configURL") == 0) {
        dsvdc_property_add_string(property, name, "https://localhost:11111");

      }

      free(name);
    }

    dsvdc_send_property_response(handle, property);
    return;
  }

  LL_FOREACH(devlist, dev)
  {
    if (strcasecmp(dsuid, dev->dsuidstring) == 0) {
      break;
    }
  }
  if (dev == NULL) {
    fprintf(stderr, "getprop_cb: unhandled dsuid %s\n", dsuid);
    dsvdc_property_free(property);
    return;
  }

  /*
   * Properties for the VDSD's
   */
  for (i = 0; i < dsvdc_property_get_num_properties(query); i++) {

    int ret = dsvdc_property_get_name(query, i, &name);
    if (ret != DSVDC_OK) {
      fprintf(stderr, "getprop_cb: error getting property name, abort\n");
      dsvdc_send_property_response(handle, property);
      return;
    }
    if (!name) {
      fprintf(stderr, "getprop_cb: not yet handling wildcard properties\n");
      //dsvdc_send_property_response(handle, property);
      continue;
    }
    printf("**** request name: %s\n", name);

    if (strcmp(name, "primaryGroup") == 0) {
      dsvdc_property_add_uint(property, "primaryGroup", 3);

    } else if (strcmp(name, "buttonInputDescriptions") == 0) {

    } else if (strcmp(name, "buttonInputSettings") == 0) {

    } else if (strcmp(name, "outputDescription") == 0) {

    } else if (strcmp(name, "outputSettings") == 0) {

    } else if (strcmp(name, "channelDescriptions") == 0) {

    } else if (strcmp(name, "channelSettings") == 0) {

    } else if (strcmp(name, "binaryInputDescriptions") == 0) {
      if ((strcmp(dev->mod->type, "NAModule1") == 0) ||
          (strcmp(dev->mod->type, "NAModule4") == 0)) {

        dsvdc_property_t *reply;
        ret = dsvdc_property_new(&reply);
        if (ret != DSVDC_OK) {
          printf("failed to allocate reply property for %s\n", name);
          free(name);
          continue;
        }

        dsvdc_property_t *nProp;
        if (dsvdc_property_new(&nProp) != DSVDC_OK) {
          break;
        }
        dsvdc_property_add_string(nProp, "name", "Battery Status");
        dsvdc_property_add_uint(nProp, "sensorFunction", 12);
        dsvdc_property_add_double(nProp, "updateInterval", 60 * 5);
        dsvdc_property_add_property(reply, "0", &nProp);

        dsvdc_property_add_property(property, name, &reply);
      }

    } else if (strcmp(name, "binaryInputSettings") == 0) {
      if ((strcmp(dev->mod->type, "NAModule1") == 0) ||
          (strcmp(dev->mod->type, "NAModule4") == 0)) {

        dsvdc_property_t *reply;
        ret = dsvdc_property_new(&reply);
        if (ret != DSVDC_OK) {
          printf("failed to allocate reply property for %s\n", name);
          free(name);
          continue;
        }

        dsvdc_property_t *nProp;
        if (dsvdc_property_new(&nProp) != DSVDC_OK) {
          break;
        }
        dsvdc_property_add_uint(nProp, "group", 8);
        dsvdc_property_add_uint(nProp, "sensorFunction", 12);
        dsvdc_property_add_property(reply, "0", &nProp);

        dsvdc_property_add_property(property, name, &reply);
      }

    } else if (strcmp(name, "sensorDescriptions") == 0) {
      dsvdc_property_t *reply;
      ret = dsvdc_property_new(&reply);
      if (ret != DSVDC_OK) {
        printf("failed to allocate reply property for %s\n", name);
        free(name);
        continue;
      }

      int n, sensorUsage, sensorType;
      char sensorName[64];
      char sensorIndex[64];

      if (strcmp(dev->mod->type, "NAModule1") == 0) {
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
          sensorType = 253;
        }
        snprintf(sensorName, 64, "%s-%s", dev->mod->name, dev->mod->values[n].data_type);

        dsvdc_property_t *nProp;
        if (dsvdc_property_new(&nProp) != DSVDC_OK) {
          break;
        }
        dsvdc_property_add_string(nProp, "name", sensorName);
        dsvdc_property_add_uint(nProp, "sensorType", sensorType);
        dsvdc_property_add_uint(nProp, "sensorUsage", sensorUsage);
        dsvdc_property_add_double(nProp, "aliveSignInterval", 300);

        snprintf(sensorIndex, 64, "%d", n);
        dsvdc_property_add_property(reply, sensorIndex, &nProp);

        printf("  dsuid %s sensor %d: %s type %d usage %d\n", dsuid, n, sensorName, sensorType, sensorUsage);
      }
      dsvdc_property_add_property(property, name, &reply);

    } else if (strcmp(name, "sensorSettings") == 0) {
      dsvdc_property_t *reply;
      ret = dsvdc_property_new(&reply);
      if (ret != DSVDC_OK) {
        printf("failed to allocate reply property for %s\n", name);
        free(name);
        continue;
      }

      char sensorIndex[64];
      int n;
      for (n = 0; n < dev->mod->values_num; n++) {
        dsvdc_property_t *nProp;
        if (dsvdc_property_new(&nProp) != DSVDC_OK) {
          break;
        }
        dsvdc_property_add_uint(nProp, "group", 48);
        dsvdc_property_add_uint(nProp, "minPushInterval", 300);
        dsvdc_property_add_double(nProp, "changesOnlyInterval", 300);

        snprintf(sensorIndex, 64, "%d", n);
        dsvdc_property_add_property(reply, sensorIndex, &nProp);
      }
      dsvdc_property_add_property(property, name, &reply);

    } else if (strcmp(name, "sensorStates") == 0) {
      dsvdc_property_t *reply;
      ret = dsvdc_property_new(&reply);
      if (ret != DSVDC_OK) {
        printf("failed to allocate reply property for %s\n", name);
        free(name);
        continue;
      }

      int idx, n;
      char* sensorIndex;
      dsvdc_property_t *sensorRequest;
      dsvdc_property_get_property_by_index(query, 0, &sensorRequest);
      if (dsvdc_property_get_name(sensorRequest, 0, &sensorIndex) != DSVDC_OK) {
        printf("****** could not parse index\n");
        idx = -1;
      } else {
        idx = strtol(sensorIndex, NULL, 10);
      }

      time_t now = time(NULL);
      netatmo_get_values();

      for (n = 0; n < dev->mod->values_num; n++) {
        if (idx >= 0 && idx != n) {
          continue;
        }

        dsvdc_property_t *nProp;
        if (dsvdc_property_new(&nProp) != DSVDC_OK) {
          break;
        }

        double val = dev->mod->values[n].value;

        dsvdc_property_add_double(nProp, "value", val);
        dsvdc_property_add_int(nProp, "age", now - dev->mod->values[n].last_query);
        dsvdc_property_add_int(nProp, "error", 0);
        dsvdc_property_add_property(reply, sensorIndex, &nProp);
      }
      dsvdc_property_add_property(property, name, &reply);

    } else if (strcmp(name, "binaryInputStates") == 0) {
      dsvdc_property_t *reply;
      ret = dsvdc_property_new(&reply);
      if (ret != DSVDC_OK) {
        printf("failed to allocate reply property for %s\n", name);
        free(name);
        continue;
      }

      int idx, n;
      char* sensorIndex;
      dsvdc_property_t *sensorRequest;
      dsvdc_property_get_property_by_index(query, 0, &sensorRequest);
      if (dsvdc_property_get_name(sensorRequest, 0, &sensorIndex) != DSVDC_OK) {
        printf("****** could not parse index\n");
        idx = -1;
      } else {
        idx = strtol(sensorIndex, NULL, 10);
      }

      dsvdc_property_t *nProp;
      if ((idx == 0) && (dsvdc_property_new(&nProp) == DSVDC_OK)) {

        bool val;
        if (strcmp(dev->mod->type, "NAModule1") == 0) {
          val = dev->mod->battery_vp < 4500; // /*for raingauge and outdoor module*/  class NABatteryLevelModule
        } if (strcmp(dev->mod->type, "NAModule4") == 0) {
          val = dev->mod->battery_vp < 4920; // /*indoor modules*/ class NABatteryLevelIndoorModul
        } else {
          val = 0;
        }

        dsvdc_property_add_bool(nProp, "value", val);
        dsvdc_property_add_int(nProp, "age", 0);
        dsvdc_property_add_int(nProp, "error", 0);
        dsvdc_property_add_property(reply, sensorIndex, &nProp);
      }
      dsvdc_property_add_property(property, name, &reply);

    } else if (strcmp(name, "name") == 0) {
      dsvdc_property_add_string(property, name, dev->mod->name);

    } else if (strcmp(name, "type") == 0) {
      dsvdc_property_add_string(property, name, "vDC");

    } else if (strcmp(name, "model") == 0) {
      char info[256];
      strcpy(info, "Station ");
      strcat(info, netatmo.base.station_name);
      dsvdc_property_add_string(property, name, info);

    } else if (strcmp(name, "modelFeatures") == 0) {
      dsvdc_property_t *nProp;
      dsvdc_property_new(&nProp);
      dsvdc_property_add_bool(nProp, "outmode", false);
      dsvdc_property_add_bool(nProp, "otypeconfig", false);
      dsvdc_property_add_property(property, name, &nProp);

    } else if (strcmp(name, "modelUID") == 0) {
      char info[256];
      if (strcmp(dev->mod->type, "NAModule1") == 0) {
        strcpy(info, "NetAtmo-Outdoor");  // raingauge and outdoor module
      } if (strcmp(dev->mod->type, "NAModule4") == 0) {
    	strcpy(info, "NetAtmo-Indoor"); // indoor modules
      } if (strcmp(dev->mod->type, "NAMain") == 0) {
        strcpy(info, "NetAtmo-Station"); // main modules
      } else {
        strcpy(info, "NetAtmo-Unknown");
      }
      dsvdc_property_add_string(property, name, info);

    } else if (strcmp(name, "vendorGuid") == 0) {
      char info[256];
      strcpy(info, "NetAtmo VDC prototype by mtr");
      strcat(info, dev->id);
      dsvdc_property_add_string(property, name, info);

    } else if (strcmp(name, "hardwareVersion") == 0) {
      dsvdc_property_add_string(property, name, "0.0.0");

    } else if (strcmp(name, "configURL") == 0) {
      dsvdc_property_add_string(property, name, "https://localhost:10000");

    } else if (strcmp(name, "hardwareModelGuid") == 0) {
      dsvdc_property_add_string(property, name, "gs1:3700730500111");

    } else if (strcmp(name, "hardwareGuid") == 0) {
      char info[256];
      char buffer[32];
      size_t n;

      strcpy(info, "macaddress:");
      sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x", dev->mod->bid[0], dev->mod->bid[1], dev->mod->bid[2],
          dev->mod->bid[3], dev->mod->bid[4], dev->mod->bid[5]);
      strcat(info, buffer);
      dsvdc_property_add_string(property, name, info);

    } else if (strcmp(name, "deviceIcon16") == 0) {
      dsvdc_property_add_bytes(property, name, deviceIcon16_png, sizeof(deviceIcon16_png));

    } else if (strcmp(name, "deviceIconName") == 0) {
      dsvdc_property_add_string(property, name, "netatmo-mtrx.png");

    } else {
      fprintf(stderr, "** Unhandled Property \"%s\"\n", name);
    }

    free(name);
  }

  dsvdc_send_property_response(handle, property);
}

int
main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
  struct sigaction action;

  bool ready = false;
  bool printed = false;
  bool announced = false;

  memset(&action, 0, sizeof(action));
  action.sa_handler = signal_handler;
  action.sa_flags = 0;
  sigfillset(&action.sa_mask);

  if (sigaction(SIGINT, &action, NULL) < 0) {
    fprintf(stderr, "Could not register SIGINT handler!\n");
    return EXIT_FAILURE;
  }

  if (sigaction(SIGTERM, &action, NULL) < 0) {
    fprintf(stderr, "Could not register SIGTERM handler!\n");
    return EXIT_FAILURE;
  }

  curl_global_init(CURL_GLOBAL_ALL);

  memset(&netatmo, 0, sizeof(netatmo_data_t));
  if (read_config() < 0) {
    fprintf(stderr, "Could not read configuration data!\n");
  }

  /* initially synchronize NetAtmo device data */
  if (netatmo_get_devices() < 0) {
    fprintf(stderr, "Could not get device data from NetAtmo service!\n");
    return EXIT_FAILURE;
  }

  /* generate a dsuid v1 for the vdc */
  if (g_vdc_dsuid[0] == 0) {
    dsuid_t gdsuid;
    dsuid_generate_v1(&gdsuid);
    dsuid_to_string(&gdsuid, g_vdc_dsuid);
    fprintf(stderr, "Generated VDC DSUID: %s\n", g_vdc_dsuid);
  }

  /* store configuration data, including the NetAtmo device setup and the VDC DSUID */
  if (write_config() < 0) {
    fprintf(stderr, "Could not write configuration data!\n");
  }

  /* initialize new library instance */
  dsvdc_t *handle = NULL;
  if (dsvdc_new(0, g_lib_dsuid, "NetAtmo", &ready, &handle) != DSVDC_OK) {
    fprintf(stderr, "dsvdc_new() initialization failed\n");
    return EXIT_FAILURE;
  }

  /* setup callbacks */
  dsvdc_set_hello_callback(handle, hello_cb);
  dsvdc_set_ping_callback(handle, ping_cb);
  dsvdc_set_bye_callback(handle, bye_cb);
  dsvdc_set_get_property_callback(handle, getprop_cb);

  while (!g_shutdown_flag) {
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
        if (queryValuesTime == 0) {
          queryValuesTime = time(NULL) + 180;
        } else if (netatmo_get_values() >= 0) {
          queryValuesTime = g_refresh_values + now;
        }
      }
    }

    if (!dsvdc_is_connected(handle)) {
      if (!printed) {
        fprintf(stderr, "vdC example: we are not connected!\n");
        printed = true;
      }
      ready = false;

      netatmo_vdcd_t* dev;
      LL_FOREACH(devlist, dev)
      {
        dev->announced = false;
      }
      announced = false;
    } else {
      printed = false;

      if (ready) {
        int v;
        netatmo_vdcd_t* dev;

        if (!announced) {
          if (dsvdc_announce_container(handle, g_vdc_dsuid, (void *) g_lib_dsuid, announce_container_cb) == DSVDC_OK) {
            announced = true;
          }
        }

        LL_FOREACH(devlist, dev)
        {
          if (dev->present && !dev->announced) {
            if (dsvdc_announce_device(handle, g_vdc_dsuid, dev->dsuidstring, (void *) NULL, announce_device_cb) == DSVDC_OK) {
              dev->announced = true;
            }
          }
          if (!dev->present && dev->announced) {
            dsvdc_device_vanished(handle, dev->dsuidstring);
            dev->announced = false;
          }
          if (dev->present) {
            dsvdc_property_t* pushEnvelope;
            dsvdc_property_t* propState;
            dsvdc_property_t* prop;

            time_t now = time(NULL);
            bool report = false;
            for (v = 0; v < dev->mod->values_num; v++) {
              // value too old (> 4h) ?
              //if (now >= dev->mod->values[v].last_query + 2400) {
              //  continue;
              //}
              // not reported values available?
              if (dev->mod->values[v].last_reported < dev->mod->values[v].last_query) {
                report = true;
              }
            }
            if (!report) {
              continue;
            }

            dsvdc_property_new(&pushEnvelope);
            dsvdc_property_new(&propState);

            for (v = 0; v < dev->mod->values_num; v++) {
              double val = dev->mod->values[v].value;

              // value too old (> 4h) ?
              //if (now >= dev->mod->values[v].last_query + 2400) {
              //  continue;
              //}
              // not reported values available?
              if (dev->mod->values[v].last_reported >= dev->mod->values[v].last_query) {
                continue;
              }
              if (dsvdc_property_new(&prop) != DSVDC_OK) {
                continue;
              }
              dsvdc_property_add_double(prop, "value", val);
              dsvdc_property_add_int(prop, "age", now - dev->mod->values[v].last_query);
              dsvdc_property_add_int(prop, "error", 0);

              char sensorIndex[64];
              snprintf(sensorIndex, 64, "%d", v);
              dsvdc_property_add_property(propState, sensorIndex, &prop);

              dev->mod->values[v].last_reported = now;
            }

            dsvdc_property_add_property(pushEnvelope, "sensorStates", &propState);
            dsvdc_push_property(handle, dev->dsuidstring, pushEnvelope);
            dsvdc_property_free(pushEnvelope);
          }
        }
      }
    }
  }

  netatmo_vdcd_t* dev;
  LL_FOREACH(devlist, dev)
  {
    dsvdc_device_vanished(handle, dev->dsuidstring);
  }
  dsvdc_cleanup(handle);

  curl_global_cleanup();
  return EXIT_SUCCESS;
}

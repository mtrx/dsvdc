/*
 Copyright (c) 2014,2015 Michael Tross <michael@tross.org>

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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libconfig.h>
#include <utlist.h>
#include <limits.h>

#include <digitalSTROM/dsuid.h>
#include <dsvdc/dsvdc.h>

#include "netatmo.h"

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
  sprintf(tmpfile, "%s.cfg.new", g_cfgfile);

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

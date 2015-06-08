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
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libconfig.h>
#include <curl/curl.h>
#include <json/json.h>
#include <utlist.h>

#include <digitalSTROM/dsuid.h>
#include <dsvdc/dsvdc.h>

#include "netatmo.h"


/* vdSD data */

const char *g_cfgfile = "netatmo.cfg";
int g_shutdown_flag = 0;
int g_debug_flag = 0;
netatmo_data_t netatmo;
netatmo_vdcd_t* devlist = NULL;

/* VDC-API data */

char g_vdc_dsuid[35] = { 0, };
char g_lib_dsuid[35] = { "053f848b85bb382198025cea1fd087f100" };

/* NetAtmo Data */

const char *g_client_id = "52823f931877590c917b23f7";
const char *g_client_secret = NULL;
char *g_access_token = NULL;
char *g_refresh_token = NULL;
time_t g_refresh_token_valid_until = 0;
time_t g_resync_devices = 60 * 60;
time_t g_refresh_values = 5 * 60;


void
signal_handler(int signum)
{
  if ((signum == SIGINT) || (signum == SIGTERM)) {
    g_shutdown_flag++;
  }
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
  dsvdc_set_hello_callback(handle, vdc_hello_cb);
  dsvdc_set_ping_callback(handle, vdc_ping_cb);
  dsvdc_set_bye_callback(handle, vdc_bye_cb);
  dsvdc_set_get_property_callback(handle, vdc_getprop_cb);
  dsvdc_set_set_property_callback(handle, vdc_setprop_cb);

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
          if (dsvdc_announce_container(handle, g_vdc_dsuid, (void *) g_lib_dsuid, vdc_announce_container_cb) == DSVDC_OK) {
            announced = true;
          }
        }

        LL_FOREACH(devlist, dev)
        {
          if (dev->present && !dev->announced) {
            if (dsvdc_announce_device(handle, g_vdc_dsuid, dev->dsuidstring, (void *) NULL, vdc_announce_device_cb)
                == DSVDC_OK) {
              dev->announced = true;
            }
          }
          if (dev->present) {
            // Test first element if there are new values
            if (dev->mod->values[0].last_reported >= dev->mod->values[0].last_query) {
              continue;
            }

            dsvdc_property_t* pushEnvelope;
            dsvdc_property_t* propState;
            dsvdc_property_t* prop;

            dsvdc_property_new(&pushEnvelope);
            dsvdc_property_new(&propState);

            for (v = 0; v < dev->mod->values_num; v++) {
              double val = dev->mod->values[v].value;
              time_t now = time(NULL);

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

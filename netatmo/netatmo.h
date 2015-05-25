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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <digitalSTROM/dsuid.h>
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


#define NETATMO_OUT_OF_MEMORY -1
#define NETATMO_AUTH_FAILED -10
#define NETATMO_BAD_CONFIG -12
#define NETATMO_DEVLIST_FAILED -13
#define NETATMO_GETMEASURE_FAILED -13
#define NETATMO_BAD_ACCESS_TOKEN -14


extern const char *g_cfgfile;
extern int g_shutdown_flag;
extern int g_debug_flag;
extern netatmo_data_t netatmo;
extern netatmo_vdcd_t* devlist;

extern char g_vdc_dsuid[35];
extern char g_lib_dsuid[35];

extern const char *g_client_id;
extern const char *g_client_secret;
extern char *g_access_token;
extern char *g_refresh_token;
extern time_t g_refresh_token_valid_until;
extern time_t g_resync_devices;
extern time_t g_refresh_values;

extern void vdc_hello_cb(dsvdc_t *handle __attribute__((unused)), const char *dsuid, void *userdata);
extern void vdc_ping_cb(dsvdc_t *handle __attribute__((unused)), const char *dsuid, void *userdata __attribute__((unused)));
extern void vdc_announce_device_cb(dsvdc_t *handle __attribute__((unused)), int code, void *arg, void *userdata __attribute__((unused)));
extern void vdc_announce_container_cb(dsvdc_t *handle __attribute__((unused)), int code, void *arg, void *userdata __attribute__((unused)));
extern void vdc_bye_cb(dsvdc_t *handle __attribute__((unused)), const char *dsuid, void *userdata);
extern bool vdc_remove_cb(dsvdc_t *handle __attribute__((unused)), const char *dsuid, void *userdata);
extern void vdc_blink_cb(dsvdc_t *handle __attribute__((unused)), char **dsuid, size_t n_dsuid, int32_t group, int32_t zone_id, void *userdata);
extern void vdc_getprop_cb(dsvdc_t *handle, const char *dsuid, dsvdc_property_t *property, const dsvdc_property_t *query, void *userdata);

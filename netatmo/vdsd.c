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


static const uint8_t g_vdsd_deviceIcon16_png[] =
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


void vdc_hello_cb(dsvdc_t *handle __attribute__((unused)), const char *dsuid, void *userdata)
{
  bool *ready = (bool *) userdata;
  *ready = true;
}

void vdc_ping_cb(dsvdc_t *handle __attribute__((unused)), const char *dsuid, void *userdata __attribute__((unused)))
{
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
}

void vdc_announce_device_cb(dsvdc_t *handle __attribute__((unused)), int code, void *arg, void *userdata __attribute__((unused)))
{
  printf("announcement of device %s returned code: %d\n", (char *) arg, code);
}

void vdc_announce_container_cb(dsvdc_t *handle __attribute__((unused)), int code, void *arg, void *userdata __attribute__((unused)))
{
  printf("announcement of container %s returned code: %d\n", (char *) arg, code);
}

void vdc_bye_cb(dsvdc_t *handle __attribute__((unused)), const char *dsuid, void *userdata)
{
  *(bool *) userdata = false;
}

bool vdc_remove_cb(dsvdc_t *handle __attribute__((unused)), const char *dsuid, void *userdata)
{
    (void)userdata;
    printf("received remove for dsuid %s\n", dsuid);

    return true;
}

void vdc_blink_cb(dsvdc_t *handle __attribute__((unused)), char **dsuid, size_t n_dsuid,
    int32_t group, int32_t zone_id, void *userdata)
{
    (void) userdata;
    size_t n;

    for (n = 0; n < n_dsuid; n++)
    {
        printf("received blink for device %s: zone %d, group %d\n", *dsuid, zone_id, group);
    }
}

void vdc_getprop_cb(dsvdc_t *handle, const char *dsuid, dsvdc_property_t *property, const dsvdc_property_t *query, void *userdata)
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
        dsvdc_property_add_string(property, name, "0.0.1");

      } else if (strcmp(name, "vendorId") == 0) {
        dsvdc_property_add_string(property, name, "michael@tross.org");

      } else if (strcmp(name, "name") == 0) {
        dsvdc_property_add_string(property, name, "digitalSTROM NetAtmo vDC");

      } else if (strcmp(name, "model") == 0) {
        dsvdc_property_add_string(property, name, "digitalSTROM NetAtmo libdSvDC vDC");

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
      dsvdc_property_add_string(property, name, "vDSD");

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
      strcpy(info, "digitalSTROM NetAtmo vDC");
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
      dsvdc_property_add_bytes(property, name,
          g_vdsd_deviceIcon16_png, sizeof(g_vdsd_deviceIcon16_png));

    } else if (strcmp(name, "deviceIconName") == 0) {
      dsvdc_property_add_string(property, name, "netatmo-mtrx.png");

    } else {
      fprintf(stderr, "** Unhandled Property \"%s\"\n", name);
    }

    free(name);
  }

  dsvdc_send_property_response(handle, property);
}

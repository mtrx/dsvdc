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

#include <curl/curl.h>
#include <json/json.h>
#include <utlist.h>

#include <digitalSTROM/dsuid.h>
#include <dsvdc/dsvdc.h>

#include "netatmo.h"


struct memory_struct
{
  char *memory;
  size_t size;
};

struct data
{
  char trace_ascii; /* 1 or 0 */
};


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
  if (NULL == jobj) {
    printf("NetAtmo access token request failed");
    return NETATMO_AUTH_FAILED;
  }

  int rval = 0;
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
      rval = NETATMO_AUTH_FAILED;
    } else {
      printf("Unknown key: %s\n", key);
    }
  }

  free(response->memory);
  free(response);
  return rval;
}

int
netatmo_get_devices()
{
  int rc, n, nd, v;

  printf("Reading device list from NetAtmo\n");

  if (NULL == g_access_token) {
    if ((rc = netatmo_get_token()) != 0) {
      return rc;
    }
  }
  if (NULL == g_access_token) {
    return NETATMO_BAD_ACCESS_TOKEN;
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

  if (NULL == g_access_token) {
    if ((rc = netatmo_get_token()) != 0) {
      return rc;
    }
  }
  if (NULL == g_access_token) {
    return NETATMO_BAD_ACCESS_TOKEN;
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

ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}

bin_PROGRAMS = vdsd-netatmo
vdsd_netatmo_SOURCES = main.c network.c configuration.c vdsd.c netatmo.h
vdsd_netatmo_CFLAGS = $(LIBCONFIG_CFLAGS) $(JSONC_CFLAGS) $(CURL_CFLAGS) $(LIBDSVDC_CFLAGS) $(LIBDSUID_CFLAGS)
vdsd_netatmo_LDADD = $(LIBCONFIG_LIBS) $(JSONC_LIBS) $(CURL_LIBS) $(LIBDSVDC_LIBS) $(LIBDSUID_LIBS)

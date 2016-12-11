# This file is part of the snmpfs project (http://snmpfs.x25.pm).
# snmpfs is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation, either version 2 of the license, or any later
# version.  See LICENSE file for further copyright and license details.

.POSIX:
.SUFFIXES:
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := all
.DELETE_ON_ERROR:

VERSION = 1.0.0

PREFIX = /usr/local
MANPREFIX = ${PREFIX}/share/man
CONFPREFIX = ${PREFIX}/etc/snmp
MOUNTPREFIX = ${DESTDIR}/net/snmp
CACHEPREFIX = ${PREFIX}/var/lib/snmp
MIBPREFIX = ${PREFIX}/share/snmp/mibs

MAKEFLAGS += --warn-undefined-variables
SHELL := bash

INCS = -I. -I/usr/include
LIBS = -L/usr/lib -lc -lcrypto -lconfig -lfuse

CC = cc
CFLAGS = -g -std=c11 -pedantic -Wall -Os ${INCS}
LDFLAGS = -s ${LIBS}

SOURCE = $(wildcard src/*.c) $(wildcard src/snmp/*.c)
OBJS = $(SOURCE:.c=.o)
DEPS = $(OBJS:.o=.d)

all: options snmpfs snmpfs.8 snmpfs.conf

options:
	@echo snmpfs build options:
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "LDFLAGS  = ${LDFLAGS}"
	@echo "CC       = ${CC}"

snmpfs: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.d: %.c src/config.h
	$(CC) $(CFLAGS) $< -MM -MT $(@:.d=.o) > $@

-include $(DEPS)

%.o: %.c %.d
	$(CC) $(CFLAGS) -o $@ -c $<

src/config.h: src/config.h.in
	sed \
	-e "s:\@SNMP_PACKAGE_VERSION\@:${VERSION}:" \
	-e "s:\@SNMP_CONF_DIR\@:${CONFPREFIX}:" \
	-e "s:\@SNMP_MOUNT_DIR\@:${MOUNTPREFIX}:" \
	-e "s:\@SNMP_CACHE_DIR\@:${CACHEPREFIX}:" \
	-e "s:\@SNMP_MIB_DIR\@:${MIBPREFIX}:g" \
	$@.in > $@

snmpfs.conf: snmpfs.conf.in
	sed \
	-e "s:\@SNMP_MOUNT_DIR\@:${MOUNTPREFIX}:" \
	-e "s:\@SNMP_CACHE_DIR\@:${CACHEPREFIX}:" \
	-e "s:\@SNMP_MIB_DIR\@:${MIBPREFIX}:g" \
	$@.in > $@

snmpfs.8: snmpfs.8.in
	sed \
	-e "s:\@SNMP_CONF_DIR\@:${CONFPREFIX}:" \
	-e "s:\@SNMP_MOUNT_DIR\@:${MOUNTPREFIX}:" \
	-e "s:\@SNMP_MIB_DIR\@:${MIBPREFIX}:" \
	-e "s:\@SNMP_CACHE_DIR\@:${CACHEPREFIX}:g" \
	$@.in > $@

clean:
	$(RM) $(OBJS) $(DEPS) snmpfs.8 snmpfs.conf \
	src/config.h snmpfs snmpfs-${VERSION}.tar.gz

dist: clean
	$(MKDIR) -p snmpfs-${VERSION}
	$(CP) LICENSE Makefile README snmpfs.8.in snmpfs.conf.in src snmpfs-${VERSION}
	$(TAR) -f snmpfs-${VERSION}.tar snmpfs-${VERSION}
	$(GZIP) snmpfs-${VERSION}.tar
	$(RM) snmpfs-${VERSION}

install: all
	@echo TODO

uninstall:
	@echo TODO

.PHONY: all options clean dist install uninstall


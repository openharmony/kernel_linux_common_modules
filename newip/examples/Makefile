# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2022 Huawei Device Co., Ltd.
#
#
CC=gcc
# CC = aarch64-linux-gnu-gcc
# CC = arm-linux-gnueabi-gcc
CFLAGS=-pthread -static -g

UT_LIST = nip_addr_cfg_demo nip_route_cfg_demo nip_tcp_server_demo nip_tcp_client_demo nip_udp_server_demo nip_udp_client_demo get_af_ninet check_nip_enable nip_addr nip_route

all: $(UT_LIST)

clean:
	rm -f $(UT_LIST)
	rm -f nip_lib.o
	rm -f libnip_lib.a


#lib
NIP_LIB     = libnip_lib.a
NIP_DEF_LIB = -L. -lnip_lib

nip_lib.o: nip_lib.c
	$(CC) -c nip_lib.c -o nip_lib.o

libnip_lib.a: nip_lib.o
	ar -rv libnip_lib.a nip_lib.o

#UT func list
nip_addr_cfg_demo: nip_addr_cfg_demo.c $(NIP_LIB)
	$(CC) $(CFLAGS) -o nip_addr_cfg_demo nip_addr_cfg_demo.c $(NIP_DEF_LIB)

nip_route_cfg_demo: nip_route_cfg_demo.c $(NIP_LIB)
	$(CC) $(CFLAGS) -o nip_route_cfg_demo nip_route_cfg_demo.c $(NIP_DEF_LIB)

nip_tcp_server_demo: nip_tcp_server_demo.c $(NIP_LIB)
	$(CC) $(CFLAGS) -o nip_tcp_server_demo nip_tcp_server_demo.c $(NIP_DEF_LIB)

nip_tcp_client_demo: nip_tcp_client_demo.c $(NIP_LIB)
	$(CC) $(CFLAGS) -o nip_tcp_client_demo nip_tcp_client_demo.c $(NIP_DEF_LIB)

nip_udp_server_demo: nip_udp_server_demo.c $(NIP_LIB)
	$(CC) $(CFLAGS) -o nip_udp_server_demo nip_udp_server_demo.c $(NIP_DEF_LIB)

nip_udp_client_demo: nip_udp_client_demo.c $(NIP_LIB)
	$(CC) $(CFLAGS) -o nip_udp_client_demo nip_udp_client_demo.c $(NIP_DEF_LIB)

get_af_ninet: get_af_ninet.c
	$(CC) $(CFLAGS) -o get_af_ninet get_af_ninet.c

check_nip_enable: check_nip_enable.c
	$(CC) $(CFLAGS) -o check_nip_enable check_nip_enable.c

nip_addr: nip_addr.c $(NIP_LIB)
	$(CC) $(CFLAGS) -o nip_addr nip_addr.c $(NIP_DEF_LIB)

nip_route: nip_route.c $(NIP_LIB)
	$(CC) $(CFLAGS) -o nip_route nip_route.c $(NIP_DEF_LIB)
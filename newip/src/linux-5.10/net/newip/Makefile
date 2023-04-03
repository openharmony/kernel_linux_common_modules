# SPDX-License-Identifier: GPL-2.0
# 
# Copyright (c) 2022 Huawei Device Co., Ltd.
#
# Makefile for the Linux newip layer
#

# net/newip/Makefile
obj-$(CONFIG_NEWIP) += newip.o

newip-objs := nip_addr.o nip_hdr_encap.o nip_hdr_decap.o nip_checksum.o af_ninet.o nip_input.o udp.o protocol.o nip_output.o nip_addrconf.o nip_addrconf_core.o route.o nip_fib.o  nip_fib_rules.o nndisc.o icmp.o tcp_nip_parameter.o devninet.o
newip-objs += tcp_nip.o ninet_connection_sock.o ninet_hashtables.o tcp_nip_output.o tcp_nip_input.o tcp_nip_timer.o nip_sockglue.o

newip-objs += nip_hooks_register.o


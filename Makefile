# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

DEPS	     := ./deps

XDP_TARGETS  := xdp_geneve xdp_redirect
USER_TARGETS := xdp_geneve_user xdp_redirect_user
USER_LIBS    := -lbpf -lm

XDP_C = ${XDP_TARGETS:=src/kernel/%.c}
XDP_OBJ = ${XDP_C:src/kernel/%.c=%.o}
USER_C := ${USER_TARGETS:=src/user/%.c}
USER_OBJ := ${USER_C:src/user/%.c=%.o}

LIBBPF_DIR  = ${DEPS}/libbpf/src
COMMON_DIR  = ${DEPS}/common
HEADERS_DIR = ${DEPS}/headers

EXTRA_DEPS  += $(COMMON_DIR)/parsing_helpers.h

include $(COMMON_DIR)/common.mk
#COMMON_OBJS := $(COMMON_DIR)/common.o

.PHONY: tags
tags:
	ctags -e -R
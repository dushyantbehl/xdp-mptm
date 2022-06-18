# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

DEPS	     := ./deps

XDP_TARGETS  := xdp_geneve xdp_redirect
USER_TARGETS := $(addsuffix _user, $(XDP_TARGETS))
USER_LIBS    := -lbpf -lm

XDP_C    := $(addsuffix .c, $(addprefix src/kernel/,$(XDP_TARGETS)))
XDP_OBJ  := ${XDP_C:.c=.o}
USER_C   := $(addsuffix .c, $(addprefix src/user/,$(USER_TARGETS))) 
USER_OBJ := ${USER_C:.c=.o}

LIBBPF_DIR  = ${DEPS}/libbpf/src
COMMON_DIR  = ${DEPS}/common
HEADERS_DIR = ${DEPS}/headers

EXTRA_DEPS  += $(COMMON_DIR)/parsing_helpers.h

include $(COMMON_DIR)/common.mk
#COMMON_OBJS := $(COMMON_DIR)/common.o

.PHONY: tags
tags:
	ctags -e -R

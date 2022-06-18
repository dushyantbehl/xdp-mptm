/* SPDX-License-Identifier: GPL-2->0 */

/* NOTE:
 * We have used the veth index as primary key for this Poc, a more realistic
 * implementation should use the inner ip as the primary key instead
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <math.h>
#include <locale.h>
#include <unistd.h>
#include <time.h>

#include "bpf-user-helpers.h"

#define TUNNEL_IFACE_MAP   "tunnel_map_iface"

int action;
u_int32_t capture_iface = -1;
u_int64_t vlid = -1;
u_int16_t flags = -1;
u_int16_t s_port = -1;
u_int16_t eth_iface = -1;
char s_addr[16];
char d_addr[16];
char s_mac[18];
char outer_d_mac[18];
char inner_d_mac[18];

void  print_usage() {
  printf("[USAGE]: v:f:p:i:c:s:d:e:t:o:q\n");
  printf("v:vlanid f:flags p:source_port i:capture_iface_index(for egress say veth0)"
         " c:redirect_iface_index(for egress say eth0) s:s_ipaddr d:d_ipdaddr e:s_mac"
         " t:outer_d_mac q:inner_d_mac a:action [ADD/DEL]\n");
}

static const struct option long_options[] = {
        {"action",      required_argument, 0,    'a'},
        {"vlid",        required_argument, 0,    'v'}, //"Geneve tunnel vlan id of <connection>", "<vlid>", true},
        {"flags",       required_argument, 0,    'f'}, //"Geneve tunnel flags of <connection>", "<flags>", true},
        {"s_port",      required_argument, 0,    'p'}, //"Source Port of <connection>", "<port>", true},
        {"iface",       required_argument, 0,    'c'}, //"Iface index capture <dev>", "<ifidx>", true},
        {"eth_iface",   required_argument, 0,    'i'}, //"Iface id redirect <dev>[eth0]", "<ifidx>", true},
        {"s_ip_addr",   required_argument, NULL, 's'}, //"Source IP address of <dev>", "<ip>", true},
        {"s_mac",       required_argument, NULL, 'e'}, //"Source MAC addr of <dev>", "<mac>", true},
        {"d_ip_addr",   required_argument, NULL, 'd'}, //"Destination IP addr of <redirect-dev>", "<ip>", true},
        {"d_mac",       required_argument, NULL, 't'}, //"Destination MAC addr of <redirect-dev>", "<mac>", true},
        {"inner_d_mac", required_argument, NULL, 'q'}, //"Inner Destination MAC address", "<mac>", true},
        {0, 0, NULL, 0}
};

int parse_params(int argc, char *argv[]) {
    int opt = 0;
    int long_index = 0;

    while( (opt = getopt_long(argc, argv, "v:f:p:i:c:s:d:e:t:a:q:", 
                                 long_options, &long_index )) != -1 ) {
      printf("opt: %c arg: %s \n", opt, optarg);
      switch (opt) {
        case 'v' : vlid = atol(optarg);
            break;
        case 'f' : flags = atoi(optarg);
            break;
        case 'p' : s_port = atoi(optarg); 
            break;
        case 'i' : eth_iface = atoi(optarg);
            break;
        case 'c' : capture_iface = atoi(optarg);
            break;
        case 's' : strncpy(s_addr, optarg, 16);
            break;
        case 'd' : strncpy(d_addr, optarg, 16);
            break;
        case 'e' : strncpy(s_mac, optarg, 18);
            break;
        case 't' : strncpy(outer_d_mac, optarg, 18);
            break;
        case 'q' : strncpy(inner_d_mac, optarg, 18);
            break;
        case 'a' :
            if(strcmp(optarg, "ADD") == 0) {
                action = MAP_ADD;
            } else if(strcmp(optarg, "DEL") == 0) {
                action = MAP_DELETE;
            } else {
                fprintf(stderr, "INVALID value for option -o %s\n", optarg);
                return -1;
            }
            break;
        default:
            fprintf(stderr, "INVALID parameter supplied %c\n", opt);
            return -1;
      }
    }

    if(action == MAP_ADD ) {
        if (vlid == -1 || flags == -1 || capture_iface == -1 ||
            eth_iface == -1 || s_addr[0] == '\0' || d_addr[0] == '\0' ||
            outer_d_mac[0] == '\0' || s_mac[0] == '\0' || inner_d_mac == '\0') {
            // if we need to add then we need all the other info to create
            // tunnel structure.
            fprintf(stderr, "operation is add but all argumnets are not provided\n");
            return -1;
        }
        printf("All arguments verified\n");
    } else if(capture_iface == -1) {
        // for delete we only need iface.
        fprintf(stderr, "operation is delete but key (-c) is not provided\n");
        return 1;
    }

    return 0;
}

tunnel_info* create_tun_info(char* s_mac, char* outer_d_mac, char* inner_d_mac,
                             u_int32_t iface, u_int16_t flags, u_int64_t vlid,
                             u_int16_t s_port, char* d_addr, char* s_addr) {

    tunnel_info *loc = (tunnel_info *)malloc(sizeof(tunnel_info));

    loc->iface = iface;
    loc->vlid = vlid;
    loc->flags = flags;
    loc->s_port = s_port;

    if (parse_mac(s_mac, loc->s_mac) < 0) {
        fprintf(stderr, "d_mac value is incorrect\n");
        return NULL;
    }
    if (parse_mac(outer_d_mac, loc->d_mac) < 0) {
        fprintf(stderr, "d_mac value is incorrect\n");
        return NULL;
    }
    if (parse_mac(inner_d_mac, loc->inner_d_mac) < 0) {
        fprintf(stderr, "inner_d_mac value is incorrect\n");
        return NULL;
    }
    loc->d_addr = parse_ipv4(d_addr);
    if (loc->d_addr == -1) {
        fprintf(stderr, "d_addr value is incorrect\n");
        return NULL;
    }
    loc->s_addr = parse_ipv4(s_addr);
    if (loc->s_addr == -1) {
        fprintf(stderr, "s_addr value is incorrect\n");
        return NULL;
    }
     return loc;
}

int main(int argc, char **argv) {

    if (parse_params(argc, argv) != 0) {
        fprintf(stderr, "parsing params failed\n");
        print_usage();
        exit(EXIT_FAILURE);
    }

    /* Open the map for geneve config */
    int tunnel_map_fd = open_bpf_map_file(PIN_BASE_DIR, TUNNEL_IFACE_MAP, NULL);
    if (tunnel_map_fd < 0) {
          fprintf(stderr, "cannot open tunnel iface map\n");
        return EXIT_FAIL_BPF;
    }

    tunnel_info *ti = NULL;
    if (action == MAP_ADD) {
        ti = create_tun_info(s_mac, outer_d_mac, inner_d_mac, eth_iface,
                             flags, vlid, s_port, d_addr, s_addr);
        if(ti == NULL) {
            fprintf(stderr, "failed creating struct\n");
            return EXIT_FAIL_OPTION;
        }
    }

    return update_map(tunnel_map_fd, action, &capture_iface, ti, 0, TUNNEL_IFACE_MAP);
}

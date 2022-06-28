/* SPDX-License-Identifier: GPL-2->0 */
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

#include <kernel/lib/headers.h>
#include <user/lib/bpf-user-helpers.h>

 /* custom ones from xdp examples */
#include <common/xdp_stats_kern_user.h>

#define TUNNEL_IFACE_MAP   "tunnel_map_iface"

typedef struct mptm_arguments {
    int action;
    u_int32_t capture_iface;
    u_int64_t vlid;
    u_int16_t flags;
    u_int16_t source_port;
    u_int16_t redirect_iface;
    char source_addr[16];
    char dest_addr[16];
    char source_mac[18];
    char outer_dest_mac[18];
    char inner_dest_mac[18];
    u_int8_t debug;
    u_int8_t tunnel;
    u_int8_t redirect;
} mptm_args;

// TODO: Update
void  print_usage() {
  printf("[USAGE]: a:t:v:f:p:I:R:s:S:d:D:M:V:\n");
  printf("v:vlanid f:flags p:source_port c:capture_iface_index(for egress say veth0)"
         " i:redirect_iface_index(for egress say eth0) s:s_ipaddr d:d_ipdaddr e:s_mac"
         " t:outer_d_mac q:inner_d_mac a:action [ADD/DEL]\n");
}

static const struct option long_options[] = {
        {"action",         required_argument, 0,    'a'},
        {"vlid",           required_argument, 0,    'v'}, //"Geneve tunnel vlan id of <connection>", "<vlid>", true},
        {"flags",          required_argument, 0,    'f'}, //"Geneve tunnel flags of <connection>", "<flags>", true},
        {"source_port",    required_argument, 0,    'p'}, //"Source Port of <connection>", "<port>", true},
        {"ingress_iface",  required_argument, 0,    'I'}, //"Iface index capture <dev>", "<ifidx>", true},
        {"redirect",       required_argument, 0,    'r'}, // to redirect packet to redirect_iface or not
        {"redirect_iface", required_argument, 0,    'R'}, //"Iface id redirect <dev>[eth0]", "<ifidx>", true},
        {"source_ip",      required_argument, NULL, 's'}, //"Source IP address of <dev>", "<ip>", true},
        {"source_mac",     required_argument, NULL, 'S'}, //"Source MAC addr of <dev>", "<mac>", true},
        {"dest_ip",        required_argument, NULL, 'd'}, //"Destination IP addr of <redirect-dev>", "<ip>", true},
        {"dest_mac",       required_argument, NULL, 'D'}, //"Destination MAC addr of <redirect-dev>", "<mac>", true},
        {"inner_dest_mac", required_argument, NULL, 'M'}, //"Inner Destination MAC address", "<mac>", true},
        {"verbose",        required_argument, NULL, 'V'},
        {"tunnel",         required_argument, NULL, 't'},
        {0, 0, NULL, 0}
};

int verify_args(mptm_args *mptm) {
    int action = mptm->action;

    switch (mptm->tunnel)
    {
    case GENEVE:
        if(action == MAP_ADD) {
            // currently we don't check vlanid and flags as they can be zero
            if (mptm->capture_iface == 0 || // mptm->vlid == 0 || mptm->flags == 0 ||
                mptm->redirect_iface == 0 || mptm->source_addr[0] == '\0' || mptm->dest_addr[0] == '\0' ||
                mptm->outer_dest_mac[0] == '\0' || mptm->source_mac[0] == '\0' || mptm->inner_dest_mac[0] == '\0') {
                // if we need to add then we need all the other info to create
                // tunnel structure.
                fprintf(stderr, "operation is add but all argumnets are not provided\n");
                return -1;
            }
            printf("All arguments verified\n");
        } else if(mptm->capture_iface == 0) {
            // for delete we only need iface.
            fprintf(stderr, "operation is delete but key (-c) is not provided\n");
            return 1;
        }
      break;
    case VLAN:
        if (action == MAP_ADD) {
            // currently we don't check vlanid as it can be zero
        } else if(mptm->capture_iface == 0) {
            // for delete we only need iface.
            fprintf(stderr, "operation is delete but key (-c) is not provided\n");
            return 1;
        }
      break;
    default:
        fprintf(stderr, "Unknown type of tunnel\n");
        return 1;
    }
    return 0;
}

int parse_params(int argc, char *argv[], mptm_args *mptm) {
    int opt = 0;
    int long_index = 0;

    while( (opt = getopt_long(argc, argv, "a:t:v:f:p:I:R:s:S:d:D:M:V:", 
                                 long_options, &long_index )) != -1 ) {
      printf("opt: %c arg: %s \n", opt, optarg);
      switch (opt) {
        case 'a' :
            if(strcmp(optarg, "ADD") == 0) {
                mptm->action = MAP_ADD;
            } else if(strcmp(optarg, "DEL") == 0) {
                mptm->action = MAP_DELETE;
            } else {
                fprintf(stderr, "INVALID value for option -o %s\n", optarg);
                return -1;
            }
            break;
        case 't' :
            mptm->tunnel = atoi(optarg);
            break;
        case 'v' : mptm->vlid = atol(optarg);
            break;
        case 'f' : mptm->flags = atoi(optarg);
            break;
        case 'p' : mptm->source_port = atoi(optarg); 
            break;
        case 'I' : mptm->capture_iface = atoi(optarg);
            break;
        case 'r' : mptm->redirect = atoi(optarg);
            break;
        case 'R' : mptm->redirect_iface = atoi(optarg);
            break;
        case 's' : strncpy(mptm->source_addr, optarg, 16);
            break;
        case 'd' : strncpy(mptm->dest_addr, optarg, 16);
            break;
        case 'S' : strncpy(mptm->source_mac, optarg, 18);
            break;
        case 'D' : strncpy(mptm->outer_dest_mac, optarg, 18);
            break;
        case 'M' : strncpy(mptm->inner_dest_mac, optarg, 18);
            break;
        case 'V' : mptm->debug = atoi(optarg);
            break;
        default:
            fprintf(stderr, "INVALID parameter supplied %c\n", opt);
            return -1;
      }
    }

    return verify_args(mptm);
}

mptm_tunnel_info* create_tun_info(mptm_args *mptm) {

    mptm_tunnel_info *tn = (mptm_tunnel_info *)malloc(sizeof(mptm_tunnel_info));

    tn->debug = mptm->debug;
    tn->tunnel_type = mptm->tunnel;
    tn->redirect = mptm->redirect;
    tn->redirect_if = mptm->redirect_iface;
    tn->flags = mptm->flags;

    switch (mptm->tunnel) {
    case VLAN: {
        struct vlan_info *vlan = (struct vlan_info *)(&tn->tnl_info.vlan);
        vlan->vlan_id = mptm->vlid;
      }
      break;
    case GENEVE: {
        struct geneve_info *geneve = (struct geneve_info *)(&tn->tnl_info.geneve);
        geneve->vlan_id = mptm->vlid;
        geneve->source_port = mptm->source_port;
        if (parse_mac(mptm->source_mac, geneve->source_mac) < 0) {
            fprintf(stderr, "source_mac value is incorrect\n");
            return NULL;
        }
        if (parse_mac(mptm->outer_dest_mac, geneve->dest_mac) < 0) {
            fprintf(stderr, "outer_dest_mac value is incorrect\n");
            return NULL;
        }
        if (parse_mac(mptm->inner_dest_mac, geneve->inner_dest_mac) < 0) {
            fprintf(stderr, "inner_d_mac value is incorrect\n");
            return NULL;
        }
        geneve->dest_addr = parse_ipv4(mptm->dest_addr);
        if (geneve->dest_addr == -1) {
            fprintf(stderr, "dest_addr value is incorrect\n");
            return NULL;
        }
        geneve->source_addr = parse_ipv4(mptm->source_mac);
        if (geneve->source_addr == -1) {
            fprintf(stderr, "source_addr value is incorrect\n");
            return NULL;
        }
      }
      break;
    default:
        break;
    }

     return tn;
}

int main(int argc, char **argv) {

    mptm_args *mptm = (mptm_args *)malloc(sizeof(mptm_args));

    if (parse_params(argc, argv, mptm) != 0) {
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

    mptm_tunnel_info *ti = NULL;
    if (mptm->action == MAP_ADD) {
        ti = create_tun_info(mptm);
        if(ti == NULL) {
            fprintf(stderr, "failed creating struct\n");
            return EXIT_FAIL_OPTION;
        }
    }

    uint32_t key = parse_ipv4(mptm->dest_addr);
    return update_map(tunnel_map_fd, mptm->action, &key, ti, 0, TUNNEL_IFACE_MAP);
}


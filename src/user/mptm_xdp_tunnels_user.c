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
#include <arpa/inet.h>

#include <kernel/lib/headers.h>
#include <user/lib/bpf-user-helpers.h>

#define str(x)  #x
#define xstr(x) str(x)

 /* custom ones from xdp examples */
#include <common/xdp_stats_kern_user.h>

// TODO: make sure this can be overridden using env or argument
#define TUNNEL_IFACE_MAP   "mptm_tunnels_map"

// TODO: VLAN also needs dest_addr as an argument.
// Key is supposed to be dest_addr so do we overload it or do something else with it?

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
    char key[16];
} mptm_args;

void  print_usage() {
  printf("\nPlease see usage:\n"
         "\t -t/--tunnel <1 for VLAN / 3 for GENEVE>\n"
         "\t tunnel VLAN:-\n"
         "\t\t -v/--vlid <vlan id>\n"
         "\t tunnel GENEVE:-\n"
         "\t\t -v/--vlid <vlan id>\n"
         "\t\t -p/--source_port <port-num>\n"
         "\t\t -I/--ingress_iface <dev-num>\n"
         "\t\t -s/--source_ip <source-ip e.g. 10.1.1.1>\n"
         "\t\t -S/--source_mac <source-mac e.g. aa:bb:cc:dd:ee:ff>\n"
         "\t\t -d/--dest_ip <dest-ip e.g. 10.1.1.1>\n"
         "\t\t -D/--dest_mac <dest-mac e.g. aa:bb:cc:dd:ee:ff>\n"
         "\t\t -M/--inner_dest_mac <inner-dest-mac e.g. aa:bb:cc:dd:ee:ff>\n"
         "\t common options:-\n"
         "\t\t -r/--redirect <1 or 0>\n"
         "\t\t -R/--redirect_iface <dev-num>\n"
         "\t\t -f/--flags <0>\n"
         "\t\t -v/--verbose <1 or 0>\n"
         "\t\t -a/--action [ADD/DEL/GET] rule\n"
         "\t\t -k/--key (inner source addr for now)\n"
        );
}

static const struct option long_options[] = {
        {"help",           no_argument,       0,    'h'},
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
        {"key",            required_argument, NULL, 'k'},
        {0, 0, NULL, 0}
};

// TODO: Make it verify redirect etc separately and tunnels separately
int verify_args(mptm_args *mptm) {
    int action = mptm->action;

    if (action == MAP_GET || action == MAP_DELETE) {
        if (mptm->key[0] == '\0') {
            fprintf(stderr, "ERR: for this operation key is needed\n");
            return -1;
        }
        return 0;
    }

    switch (mptm->tunnel)
    {
    case GENEVE:
        if(action == MAP_ADD) {
            // currently we don't check vlanid and flags as they can be zero
            if (mptm->capture_iface == 0 || // mptm->vlid == 0 || mptm->flags == 0 || mptm->redirect_iface == 0 ||
                mptm->source_addr[0] == '\0' || mptm->dest_addr[0] == '\0' ||
                mptm->outer_dest_mac[0] == '\0' || mptm->source_mac[0] == '\0' || mptm->inner_dest_mac[0] == '\0') {
                // if we need to add then we need all the other info to create
                // tunnel structure.
                fprintf(stderr, "ERR: operation is add but all argumnets are not provided\n");
                return -1;
            }
        } else if(mptm->dest_addr[0] == '\0') {
            // for delete we only need key.
            fprintf(stderr, "ERR: operation is delete but key (-c) is not provided\n");
            return 1;
        }
      break;
    case VLAN:
        if (action == MAP_ADD) {
            // currently we don't check vlanid as it can be zero
        } else if(mptm->dest_addr[0] == '\0') {
            // for delete we only need key.
            fprintf(stderr, "ERR: operation is delete but key (-c) is not provided\n");
            return 1;
        }
      break;
    default:
        fprintf(stderr, "ERR: Unknown type of tunnel\n");
        return 1;
    }

    fprintf(stdout, "Arguments verified\n");
    return 0;
}

// Change name of verbose to logs (-l/--enable_logs)
int parse_params(int argc, char *argv[], mptm_args *mptm) {
    int opt = 0;
    int long_index = 0;

    while( (opt = getopt_long(argc, argv, "h:a:t:v:f:p:I:R:s:S:d:D:M:V:k:", 
                                 long_options, &long_index )) != -1 ) {
      printf("opt: %c arg: %s \n", opt, optarg);
      switch (opt) {
        case 'h' :
            print_usage();
            exit(0);
        case 'a' :
            if(strcmp(optarg, "ADD") == 0) {
                mptm->action = MAP_ADD;
            } else if(strcmp(optarg, "DEL") == 0) {
                mptm->action = MAP_DELETE;
            } else if(strcmp(optarg, "GET") == 0) {
                mptm->action = MAP_GET;
            } else {
                fprintf(stderr, "ERR: INVALID value for option -o %s\n", optarg);
                return -1;
            }
            break;
        case 't' :
            if(strcmp(optarg, "VLAN") == 0) {
                mptm->tunnel = VLAN;
            } else if(strcmp(optarg, "GENEVE") == 0) {
                mptm->tunnel = GENEVE;
            } else {
                fprintf(stderr, "ERR: INVALID value for tunnel -t %s\n", optarg);
                return -1;
            }
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
        case 'k' : strncpy(mptm->key, optarg, 16);
            break;
        default:
            fprintf(stderr, "ERR: INVALID parameter supplied %c\n", opt);
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
            fprintf(stderr, "ERR: source_mac value is incorrect\n");
            return NULL;
        }
        if (parse_mac(mptm->outer_dest_mac, geneve->dest_mac) < 0) {
            fprintf(stderr, "ERR: outer_dest_mac value is incorrect\n");
            return NULL;
        }
        if (parse_mac(mptm->inner_dest_mac, geneve->inner_dest_mac) < 0) {
            fprintf(stderr, "ERR: inner_d_mac value is incorrect\n");
            return NULL;
        }
        geneve->dest_addr = parse_ipv4(mptm->dest_addr);
        if (geneve->dest_addr == -1) {
            fprintf(stderr, "ERR: dest_addr value is incorrect\n");
            return NULL;
        }
        geneve->source_addr = parse_ipv4(mptm->source_addr);
        if (geneve->source_addr == -1) {
            fprintf(stderr, "ERR: source_addr value is incorrect\n");
            return NULL;
        }
      }
      break;
    default:
        break;
    }

     return tn;
}

char *get_tunnel_name(uint8_t tunnel) {
    char *tunnel_name = NULL;
    switch (tn->tunnel)
    {
    case GENEVE:
        *tunnel_name = xstr(GENEVE);
        break;
    case VLAN:
        *tunnel_name = xstr(VLAN);
        break;
    case VXLAN:
        *tunnel_name = xstr(VXLAN);
        break;
    default:
        *tunnel_name = "UNKNOWN";
        break;
    }
    return tunnel_name;
}

char *decode_ipv4(uint32_t ip) {
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    return inet_ntoa(ip_addr);
}

#define decode_mac(mac, eth) ({ \
    char eth[18];               \
    sprintf(eth, "%x:%x:%x:%x:%x:%x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);\
    eth;\
})

void dump_tunnel_info(mptm_tunnel_info *tn) {
    printf("Tunnel info element - {\n");
    printf("debug = %u\n", tn->debug);
    printf("redirect = %u\n", tn->redirect);
    printf("redirect_if = %u\n", tn->redirect_if);
    printf("flags = %u\n", tn->flags);
    printf("tunnel_type = %s\n", get_tunnel_name(tn->tunnel_type));
    switch (tn->tunnel_type)
    {
    case VLAN: {
        struct vlan_info *vlan = (struct vlan_info *)(&tn->tnl_info.vlan);
        printf("vlan_id = %u\n", vlan->vlan_id);
    }
    break;
    case GENEVE: {
        struct geneve_info *geneve = (struct geneve_info *)(&tn->tnl_info.geneve);
        printf("vlan_id = %u\n",geneve->vlan_id);
        printf("source_port = %u\n",geneve->source_port);
        printf("source_mac = %s\n",decode_mac(geneve->source_mac));
        printf("outer_dest_mac = %s\n", decode_mac(geneve->dest_mac));
        printf("inner_dest_mac = %s\n", decode_mac(geneve->inner_dest_mac));
        printf("dest_addr = %s\n", decode_ipv4(geneve->dest_addr));
        printf("source_addr = %s\n", decode_ipv4(geneve->source_addr));
    }
    break;
    default:
        break;
    }
    printf("}\n");
}

int main(int argc, char **argv) {

    mptm_args *mptm = (mptm_args *)malloc(sizeof(mptm_args));

    if (parse_params(argc, argv, mptm) != 0) {
        fprintf(stderr, "ERR: parsing params failed\n");
        print_usage();
        exit(EXIT_FAILURE);
    }

    /* Open the map for geneve config */
    int tunnel_map_fd = open_bpf_map_file(PIN_BASE_DIR, TUNNEL_IFACE_MAP, NULL);
    if (tunnel_map_fd < 0) {
          fprintf(stderr, "ERR: cannot open tunnel iface map\n");
        return EXIT_FAIL_BPF;
    }

    fprintf(stdout, "Opened bpf map file %s/%s\n", PIN_BASE_DIR, TUNNEL_IFACE_MAP);

    uint32_t key = parse_ipv4(mptm->key);
    fprintf(stdout, "Key (source ip) is %d\n", key);

    int ret = EXIT_OK;

    switch (mptm->action)
    {
    case MAP_GET: {
        void *elem = (void *)lookup_map(tunnel_map_fd, &key, TUNNEL_IFACE_MAP);
        mptm_tunnel_info *ti = (mptm_tunnel_info *)elem;
        dump_tunnel_info(ti);
        break;
    }
    case MAP_ADD: {
        mptm_tunnel_info *ti = NULL;
        fprintf(stdout, "Creating tunnel info object......");
        ti = create_tun_info(mptm);
        if(ti == NULL) {
            fprintf(stderr, "ERR: failed creating struct\n");
            return EXIT_FAIL_OPTION;
        }
        fprintf(stdout, "created\n");
        ret = update_map(tunnel_map_fd, MAP_ADD, &key, ti, 0, TUNNEL_IFACE_MAP);
        break;
    }
    case MAP_DELETE:
        ret = update_map(tunnel_map_fd, MAP_DELETE, &key, NULL, 0, TUNNEL_IFACE_MAP);
        break;
    }

    return ret;
}



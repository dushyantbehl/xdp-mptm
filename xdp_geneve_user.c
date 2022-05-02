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

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <linux/bpf.h>

/* custom ones from xdp examples */
#include <common/common_user_bpf_xdp.h>
#include <common/common_params.h>
#include <common/xdp_stats_kern_user.h>
#include <common/headers.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define ADD 1
#define DELETE 0

#define PIN_BASE_DIR       "/sys/fs/bpf"
#define TUNNEL_IFACE_MAP  "tunnel_map_iface"
#define REDIRECT_MAP       "redirect_map"

u_int16_t c_iface = -1;
char s_mac[18];
char d_mac[18];
char inner_d_mac[18];
char s_addr[16];
char d_addr[16];
u_int16_t flags = -1;
u_int64_t vlid = -1;
u_int32_t iface = -1;
u_int16_t s_port = -1;
int operation;
int redirect_iface_id =-1;

/************************** Parsing functions ****************************/

static inline int validate_mac_u8(char *str, unsigned char *x) {
    unsigned long z;
    z = strtoul(str, NULL, 16);
    if (z > 0xff)
        return -1;
    if (x)
        *x = z;
    return 0;
}

static inline int parse_mac(char *str, unsigned char mac[ETH_ALEN]) {
    if (validate_mac_u8(str, &mac[0]) < 0)
        return -1;
    if (validate_mac_u8(str + 3, &mac[1]) < 0)
        return -1;
    if (validate_mac_u8(str + 6, &mac[2]) < 0)
        return -1;
    if (validate_mac_u8(str + 9, &mac[3]) < 0)
        return -1;
    if (validate_mac_u8(str + 12, &mac[4]) < 0)
        return -1;
    if (validate_mac_u8(str + 15, &mac[5]) < 0)
        return -1;
    return 0;
}

/*
  Parse an ipv4 address and put the content in an integer with individual
  subnets bit shifted by 8.

  tunnel_info expects the d_addr and s_addr to be in __be32 format
  __be32 is nothing but uint32_t but naming here helps in 
  identifying the way this integer is to be created.
*/
__be32 inline parse_ipv4(char ipadr[]) {
    __be32 addr = 0, val;
    char *tok = strtok(ipadr,".");
    for (int i=0; i<4; i++) {
        val = strtol(tok, NULL, 10);
        if (tok == NULL || val > 255) {
            fprintf(stderr, "Passed ipaddr %s is invalid.\n", ipadr);
            return -1;
        }
        addr = addr<<8 + val;
        tok = strtok(NULL,".");
    }
    return(addr);
}

void  print_usage() {
  printf("[USAGE]: v:f:p:i:c:s:d:e:t:o:q:r\n");
  printf("v:vlanid f:flags p:source_port i:capture_iface_index(for egress say veth0)"
         " c:redirect_iface_index(for egress say eth0) s:s_ipaddr d:d_ipdaddr e:s_mac"
         " t:d_mac o: operation r:redirect_iface_index(for ingress say geneve0) q:inner_d_mac [ADD/DEL]\n");
}

static const struct option long_options[] = {
        {"vlid",              required_argument, 0,    'v'}, //"Geneve tunnel vlan id of <connection>", "<vlid>", true},
        {"operation",         required_argument, 0,    'o'},
        {"flags",             required_argument, 0,    'f'}, //"Geneve tunnel flags of <connection>", "<flags>", true},
        {"s_port",            required_argument, 0,    'p'}, //"Source Port of <connection>", "<port>", true},
        {"iface",             required_argument, 0,    'i'}, //"Iface id redirect <dev>[NOT enabled]", "<ifidx>", true},
        {"c_iface",           required_argument, 0,    'c'}, //"Iface index capture <dev>", "<ifidx>", true},
        {"s_ip_addr",         required_argument, NULL, 's'}, //"Source IP address of <dev>", "<ip>", true},
        {"d_ip_addr",         required_argument, NULL, 'd'}, //"Destination IP addr of <redirect-dev>", "<ip>", true},
        {"s_mac",             required_argument, NULL, 'e'}, //"Source MAC addr of <dev>", "<mac>", true},
        {"d_mac",             required_argument, NULL, 't'}, //"Destination MAC addr of <redirect-dev>", "<mac>", true},
        {"inner_d_mac",       required_argument, NULL, 'q'}, //"Inner Destination MAC address", "<mac>", true},
        {"redirect_iface_id", required_argument, 0,    'r'}, //"Program redirect map as well", "<port>", true},
        {0, 0, NULL, 0}
};

int parse_params(int argc, char *argv[]) {
    int opt = 0;
    int long_index = 0;

    while( (opt = getopt_long(argc, argv, "v:f:p:i:c:s:d:e:t:o:q:r:", 
                                 long_options, &long_index )) != -1 ) {
      printf("opt: %c arg: %s \n", opt, optarg);
      switch (opt) {
        case 'v' : vlid = atol(optarg);
            break;
        case 'f' : flags = atoi(optarg);
            break;
        case 'p' : s_port = atoi(optarg); 
            break;
        case 'i' : iface = atoi(optarg);
            break;
        case 'c' : c_iface = atoi(optarg);
            break;
        case 's' : strncpy(s_addr, optarg, 16);
            break;
        case 'd' : strncpy(d_addr, optarg, 16);
            break;
        case 'e' : strncpy(s_mac,optarg,18);
            break;
        case 't' : strncpy(d_mac, optarg, 18);
            break;
        case 'q' : strncpy(inner_d_mac, optarg, 18);
            break;
        case 'r' : redirect_iface_id = atoi(optarg);
            break;    
        case 'o' :
            if(strcmp(optarg, "ADD") == 0) {
                operation = ADD;
            } else if(strcmp(optarg, "DEL") == 0) {
                operation = DELETE;
            } else {
                fprintf(stderr, "INVALID value for option -o %s\n", optarg);
                return -1;
            }
            break;
        default:
            fprintf(stderr, "INVALID parameter supplied %s\n", opt);
            return -1;
      }
    }

    // TODO: explain
    if(redirect_iface_id == 1) {
        if (operation == ADD && (c_iface == -1 || iface == -1)) {
              return -1;
        }else if(iface == -1) {
              return -1;
        }
    }

    // TODO: explain
    if(operation == ADD && (vlid == -1 || flags == -1 || iface == -1 ||
       c_iface == -1 || s_addr[0] == '\0' || d_addr[0] == '\0' ||
       d_mac[0] == '\0' || s_mac[0] == '\0')) {
        return -1;
    } else if(iface == -1) {
        return 1;
    }
       return 0;
}

tunnel_info* create_tun_info(char* s_mac, char* d_mac, char* inner_d_mac,
                             u_int16_t iface, u_int16_t flags, u_int64_t vlid,
                             u_int16_t s_port, char* d_addr, char* s_addr) {

    tunnel_info *loc = (tunnel_info *)malloc(sizeof(tunnel_info));

    loc->iface = iface;
    loc->vlid = vlid;
    loc->flags = flags;
    loc->s_port = s_port;

    if (parse_mac(d_mac, loc->d_mac) < 0) {
        fprintf(stderr, "ERR: d_mac value is incorrect\n");
        return NULL;
    }
    if (parse_mac(s_mac, loc->s_mac) < 0) {
        fprintf(stderr, "ERR: d_mac value is incorrect\n");
        return NULL;
    }
    if (parse_mac(inner_d_mac, loc->inner_d_mac) < 0) {
        fprintf(stderr, "ERR: inner_d_mac value is incorrect\n");
        return NULL;
    }
    loc->d_addr = parse_ipv4(d_addr);
    if (loc->d_addr == -1) {
        fprintf(stderr, "ERR: d_addr value is incorrect\n");
        return NULL;
    }
    loc->s_addr = parse_ipv4(s_addr);
    if (loc->s_addr == -1) {
        fprintf(stderr, "ERR: s_addr value is incorrect\n");
        return NULL;
    }
     return loc;
}

/* Calls bpf update/delete elem based on the operation. */
int update_map(int mapfd, int operation, void *key, void *value, uint64_t flags, char *map_name) {
    int ret;
    switch (operation) {
      case DELETE:
        printf("operation is delete, deleting %s entry\n", map_name);
        ret = bpf_map_delete_elem(mapfd, key);
        break;
      case ADD:
        printf("operation is add, adding %s entry\n", map_name);
        ret = bpf_map_update_elem(mapfd, key, value, flags);
        break;
    }
    if(ret != 0){
        fprintf(stderr, "ERR: updating map %s, errno %d\n", map_name, errno);
        return EXIT_FAIL_BPF;
    }
    return EXIT_OK;
}

int main(int argc, char **argv) {
    int ret;
    int tunnel_map_fd, redirect_map_fd;

    if (parse_params(argc, argv) != 0) {
        fprintf(stderr, "ERR: parsing params\n");
        print_usage();
        exit(EXIT_FAILURE);
    }

    printf("Using map dir: %s, iface %d \n", PIN_BASE_DIR, iface);

    if (redirect_iface_id != -1) {
        /* Make map for redirection port entries */
        redirect_map_fd = open_bpf_map_file(PIN_BASE_DIR, REDIRECT_MAP, NULL);
        if (redirect_map_fd < 0) {
              fprintf(stderr, "ERR: opening redirect map\n");
            return EXIT_FAIL_BPF;
        }
        printf("redirect iface id is set to %d", redirect_iface_id);
        return update_map(redirect_map_fd, operation, &redirect_iface_id, &iface, 0, "redirect");
    }

    /* Open the map for geneve config */
    tunnel_map_fd = open_bpf_map_file(PIN_BASE_DIR, TUNNEL_IFACE_MAP, NULL);
    if (tunnel_map_fd < 0) {
          fprintf(stderr, "ERR: opening tunnel iface map\n");
        return EXIT_FAIL_BPF;
    }

    tunnel_info *ti = NULL;
    if (operation == ADD) {
        ti = create_tun_info(s_mac, d_mac, inner_d_mac, c_iface,
                                          flags, vlid, s_port, d_addr, s_addr);
        if(ti == NULL) {
            fprintf(stderr, "ERR: creating struct\n");
            return EXIT_FAIL_OPTION;
        }
    }

    return update_map(tunnel_map_fd, operation, &iface, ti, 0, "tunnel iface");
}
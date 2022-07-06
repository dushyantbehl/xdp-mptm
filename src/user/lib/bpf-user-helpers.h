/* SPDX-License-Identifier: GPL-2->0 */

/* BOILER PLATE COMMON TO USERS */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <linux/bpf.h>

#include <common/common_defines.h>
#include <common/common_user_bpf_xdp.h>

#define PIN_BASE_DIR "/sys/fs/bpf"
#define MAP_ADD 0
#define MAP_DELETE 1

/* Calls bpf update/delete elem based on the action. */
int update_map(int mapfd, int action, void *key, void *value,
               uint64_t flags, char *map_name) {
    int ret;
    switch (action) {
      case MAP_DELETE:
        printf("action is delete, deleting %s entry\n", map_name);
        ret = bpf_map_delete_elem(mapfd, key);
        break;
      case MAP_ADD:
        printf("action is add, adding %s entry\n", map_name);
        ret = bpf_map_update_elem(mapfd, key, value, flags);
        break;
    }
    if(ret != 0){
        fprintf(stderr, "ERR: updating map %s, errno %d\n", map_name, errno);
        return EXIT_FAIL_BPF;
    }
    return EXIT_OK;
}

/************************** Parsing functions ****************************/

int validate_mac_u8(char *str, unsigned char *x) {
    unsigned long z;
    z = strtoul(str, NULL, 16);
    if (z > 0xff)
        return -1;
    if (x)
        *x = z;
    return 0;
}

int parse_mac(char *str, unsigned char mac[ETH_ALEN]) {
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
  [10, 10, 1, 2] becomes 10100102
*/
uint32_t parse_ipv4(char _ipadr[]) {

    char ipadr[16];
    uint32_t addr = 0, val;

    // Make a copy of the string before breaking it down
    strlcpy(ipadr, _ipadr, 16);

    char *tok = strtok(ipadr,".");
    for (int i=0; i<4; i++) {
        val = strtol(tok, NULL, 10);
        if (tok == NULL || val > 255) {
            fprintf(stderr, "Passed ipaddr %s is invalid.\n", ipadr);
            return -1;
        }
        addr = ((addr<<8) + val);
        tok = strtok(NULL,".");
    }
    if (addr == 0) {
        fprintf(stderr, "Passed ipaddr is 0.0.0.0, might not be valid\n");
    }
    return(addr);
}

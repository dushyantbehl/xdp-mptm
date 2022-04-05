/* SPDX-License-Identifier: GPL-2->0 */

/* NOTE:
 * We have used the veth index as primary key for this Poc, a more realistic
 * implementation should use the inner ip as the primary key instead*/
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


#include <common/common_user_bpf_xdp.h>
#include <common/common_params.h>
#include <common/xdp_stats_kern_user.h>
#include <common/headers.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

u_int16_t c_iface=-1;
char s_mac[18];
char d_mac[18];
char inner_d_mac[18];
char s_addr[16];
char d_addr[16];
//u_int32_t d_addr = 0x9EFECA09;
//u_int32_t s_addr = 0xBAFECA09;
u_int16_t flags =-1;
u_int64_t vlid =-1;
u_int32_t iface = -1;
u_int16_t s_port = -1;
int is_add =0;

int redirect_iface_id =-1;

void  print_usage(){
  printf("[USAGE]: v:f:p:i:c:s:d:e:t:o:q:r\n");
  printf("v:vlanid f:flags p:source_port i:capture_iface_index(for egress say veth0) c:redirect_iface_index(for egress say eth0) s:s_ipaddr d:d_ipdaddr e:s_mac t:d_mac o: operation r:redirect_iface_index(for ingress say geneve0) q:inner_d_mac [ADD/DEL]\n");
}


static const struct option long_options[] = {
        {"vlid", required_argument,       0,  'v' },
        {"operation", required_argument,       0,  'o' },
        //"Geneve tunnel vlan id of <connection>", "<vlid>", true },
        {"flags", required_argument,       0,  'f' },
        //"Geneve tunnel flags of <connection>", "<flags>", true },
        {"redirect_iface_id", required_argument,       0,  'r' },
        //"Program redirect map as well", "<port>", true },
        {"s_port",    required_argument, 0,  'p' },
        //"Source Port of <connection>", "<port>", true },
        {"iface",   required_argument, 0,  'i' },
        //"Iface index redirect <dev>[NOT enabled]", "<ifidx>", true },
        {"c_iface",      required_argument,       0,  'c' },
        //"Iface index capture <dev>", "<ifidx>", true },
        {"s_ip_addr", required_argument,       NULL,  's' },
        //"Source IP address of <dev>", "<ip>", true },
        {"d_ip_addr",    required_argument, NULL,  'd' },
        //"Destination IP address of <redirect-dev>", "<ip>", true },
        {"s_mac",   required_argument, NULL,  'e' },
        //"Source MAC address of <dev>", "<mac>", true },
        {"d_mac",   required_argument, NULL,  't' },
        //"Destination MAC address of <redirect-dev>", "<mac>", true },
        {"inner_d_mac",   required_argument, NULL,  'q' },
        //"Inner Destination MAC address", "<mac>", true },
        {"inner_d_mac",   required_argument, NULL,  'q' },
	{0,           0, NULL,  0   }
    };

int parse_params(int argc, char *argv[]) {
    int opt= 0;
    int long_index =0;

    while ((opt = getopt_long(argc, argv,"v:f:p:i:c:s:d:e:t:o:q:r:", 
                   long_options, &long_index )) != -1) {
      printf("opt: %c arg: %s \n",opt,optarg);
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
	     case 's' : strncpy(s_addr,optarg,16);
                 break;
             case 'd' : strncpy(d_addr,optarg,16);
                 break;
             case 'e' : strncpy(s_mac,optarg,18);
                 break;
             case 't' : strncpy(d_mac,optarg,18);
                 break;
             case 'q' : strncpy(inner_d_mac,optarg,18);
                 break;
             case 'r' : redirect_iface_id = atoi(optarg);
		break;	
	     case 'o' : if(strcmp(optarg,"ADD")==0) is_add = 1;
		   else if(strcmp(optarg,"DEL")==0) is_add = 0;
		   else{
			     printf("INVALID OPt\n");
			     print_usage();
			     exit(EXIT_FAILURE);
		     }
		  break;
             default: print_usage(); 
                 exit(EXIT_FAILURE);
        }
    }
    if(redirect_iface_id==1){
	    if(is_add==1 &&(c_iface==-1||iface==-1)){
      		print_usage();
      		return -1;
	    }else if(iface==-1){
      		print_usage();
      		return -1;
	    }
    }

    if(is_add==1 && (vlid==-1 || flags==-1 || iface==-1 || c_iface==-1 || s_addr[0]=='\0' || d_addr[0]=='\0' || d_mac[0] == '\0' || s_mac[0] == '\0')){
      print_usage();
      return -1;
    }else if(iface==-1){
	    print_usage();
	    return 1;
    }
       return 0;
}

static int parse_u8(char *str, unsigned char *x)
{
	unsigned long z;

	z = strtoul(str, 0, 16);
	if (z > 0xff)
		return -1;

	if (x)
		*x = z;

	return 0;
}

static int parse_mac(char *str, unsigned char mac[ETH_ALEN])
{
	if (parse_u8(str, &mac[0]) < 0)
		return -1;
	if (parse_u8(str + 3, &mac[1]) < 0)
		return -1;
	if (parse_u8(str + 6, &mac[2]) < 0)
		return -1;
	if (parse_u8(str + 9, &mac[3]) < 0)
		return -1;
	if (parse_u8(str + 12, &mac[4]) < 0)
		return -1;
	if (parse_u8(str + 15, &mac[5]) < 0)
		return -1;

	return 0;
}

u_int32_t parse_ip(char ipadr[]){
	//TODO: add valid ip check
    u_int32_t num=0,val;
    int p=24;
    char *tok,*ptr;
    tok=strtok(ipadr,".");
    while( tok != NULL){
        val=strtol(tok,&ptr,10);
        num+=  val * (long)pow(2,p);
        p=p-8;
        tok=strtok(NULL,".");
    }
    return(num);
}

const char *pin_base_dir =  "/sys/fs/bpf";
tunnel_info loc;
tunnel_info* make_struct(char* s_mac,char* d_mac,char* inner_d_mac, u_int16_t iface, u_int16_t flags, 
		u_int64_t vlid, u_int16_t s_port, char* d_addr, char* s_addr){

	loc.iface = iface;
	loc.vlid = vlid;
	loc.flags = flags;
	loc.s_port = s_port;

	if(parse_mac(d_mac,loc.d_mac)<0){
		fprintf(stderr,"Err: d_mac value is incorrect\n");
		return NULL;
	}
	if(parse_mac(s_mac,loc.s_mac)<0){
		fprintf(stderr,"Err: d_mac value is incorrect\n");
		return NULL;
	}

	if(parse_mac(inner_d_mac,loc.inner_d_mac)<0){
		fprintf(stderr,"Err: inner_d_mac value is incorrect\n");
		return NULL;
	}
	loc.d_addr=parse_ip(d_addr);
	if(loc.d_addr<0){
		fprintf(stderr,"Err: d_addr value is incorrect\n");
		return NULL;
	}
	loc.s_addr=parse_ip(s_addr);
	if(loc.s_addr<0){
		fprintf(stderr,"Err: s_addr value is incorrect\n");
		return NULL;
	}
 	return &loc;
}

int main(int argc, char **argv)
{
	
	int map_fd;
	
	if(parse_params(argc,argv)!=0){
		fprintf(stderr, "ERR: parsing params\n");
		return EXIT_FAIL_OPTION;
	}

	/* Open the map for geneve config */
	map_fd = open_bpf_map_file(pin_base_dir, "tunnel_map_iface", NULL);
	if (map_fd < 0) {
	  	fprintf(stderr,"ERR: opening map\n");
		return EXIT_FAIL_BPF;
	}

	printf("map dir: %s iface: %d \n", pin_base_dir,iface);

	/* Make map for redirection port entries*/
	int redirect_map_fd = open_bpf_map_file(pin_base_dir, "redirect_map", NULL);
	if (redirect_map_fd < 0) {
	  	fprintf(stderr,"ERR: opening redirect map\n");
		return EXIT_FAIL_BPF;
	}
	if(redirect_iface_id!=-1 && is_add==-1){
		//delete entry here...
		int ret= bpf_map_delete_elem(redirect_map_fd,&redirect_iface_id);
		if(ret != 0){
			fprintf(stderr,"ERR: updating map\n");
			return EXIT_FAIL_BPF;
		}
		return EXIT_OK;
	}
//////////////
	if(redirect_iface_id!=-1 && is_add==1){
		int ret = bpf_map_update_elem(redirect_map_fd, &redirect_iface_id, &iface, 0);
		if(ret != 0){
			printf("errno: %d\n",errno);
			fprintf(stderr,"ERR: updating map\n");
			return EXIT_FAIL_BPF;
		}
		return EXIT_OK;
	}
	///////////
	if(is_add==0){//delete entry
		//delete entry here...
		int ret= bpf_map_delete_elem(map_fd,&iface);
		if(ret != 0){
			fprintf(stderr,"ERR: updating map\n");
			return EXIT_FAIL_BPF;
		}
		return EXIT_OK;
	}
	tunnel_info *tn = make_struct(s_mac, d_mac, inner_d_mac, c_iface,  flags, 
		 vlid,  s_port, d_addr, s_addr);
	if(tn ==NULL){
		fprintf(stderr, "ERR: creating struct\n");
		return EXIT_FAIL_OPTION;
	}
	int ret = bpf_map_update_elem(map_fd, &iface, tn, 0);
	if(ret != 0){
	  printf("errno: %d\n",errno);
	  fprintf(stderr,"ERR: updating map\n");
	  return EXIT_FAIL_BPF;
	}
	return EXIT_OK;
}

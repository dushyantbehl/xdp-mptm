#!/usr/bin/env bash

# set -x

if [[ $EUID -ne 0 ]]; then
    echo "You must be root to run this script"
    exit 1
fi

IFACE_NAME="$1"
PROG_LOAD_LOC="/sys/fs/bpf/genevenew"
PROG_NAME="xdp_geneve.o""


if [[ -z "${IFACE_NAME}" ]]; then
      echo "Usage: ./xdp_geneve_loader <IFACE_NAME>"
      exit 1

fi


load()
{
prog loadall xdp_prog_kern_02.o ${PROG_LOAD_LOC} type xdp
}

attach()
{
bpftool net attach xdp id ${PROG_ID} dev ${IFACE_NAME} overwrite
}


clean()
{


}

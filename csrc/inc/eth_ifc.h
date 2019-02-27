#ifndef ETH_IFC_H
#define ETH_IFC_H

#include "zerynth.h"

typedef struct _ethdrv {
    VEvent ip_event;
    VEvent linked_event;
    ip_addr_t ip;
    ip_addr_t mask;
    ip_addr_t gw;
    ip_addr_t dns;
    uint8_t error;
    uint8_t connected;
    uint8_t has_link_info;
} EthDrv_t;

extern EthDrv_t eth_drv;

#endif
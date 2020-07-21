/*
* @Author: lorenzo
* @Date:   2019-01-10 10:21:35
* @Last Modified by:   Lorenzo
* @Last Modified time: 2019-01-15 17:44:40
*/

#include "xmc_eth_mac.h"
#include "xmc_gpio.h"

#include "lwip/prot/dhcp.h"
#include "lwip/dhcp.h"
#include "lwip/ip_addr.h"
#include "lwip/tcpip.h"
#include "netif/etharp.h"
#include "ethernetif.h"

#include "zerynth_sockets.h"
#include "zerynth_ssl.h"

#define ZERYNTH_PRINTF
#include "zerynth.h"
#include "zerynth_sockets.h"
#include "eth_ifc.h"

// #define debug(...) printf(__VA_ARGS__)

/*int  snprintf(char* buffer, size_t count, const char* format, ...){return 0;}*/
/*int vsnprintf(char* buffer, size_t count, const char* format, va_list va){return 0;}*/



EthDrv_t eth_drv;
SocketAPIPointers xmc4eth_api;

/* MAC ADDRESS*/
#define MAC_ADDR0   0x00
#define MAC_ADDR1   0x00
#define MAC_ADDR2   0x45
#define MAC_ADDR3   0x19
#define MAC_ADDR4   0x03
#define MAC_ADDR5   0x00

#define XMC_ETH_MAC_NUM_RX_BUF (4)
#define XMC_ETH_MAC_NUM_TX_BUF (8)

// static __ALIGNED(4) XMC_ETH_MAC_DMA_DESC_t rx_desc[XMC_ETH_MAC_NUM_RX_BUF] __attribute__((section ("ETH_RAM")));
// static __ALIGNED(4) XMC_ETH_MAC_DMA_DESC_t tx_desc[XMC_ETH_MAC_NUM_TX_BUF] __attribute__((section ("ETH_RAM")));
// static __ALIGNED(4) uint8_t rx_buf[XMC_ETH_MAC_NUM_RX_BUF][XMC_ETH_MAC_BUF_SIZE] __attribute__((section ("ETH_RAM")));
// static __ALIGNED(4) uint8_t tx_buf[XMC_ETH_MAC_NUM_TX_BUF][XMC_ETH_MAC_BUF_SIZE] __attribute__((section ("ETH_RAM")));

static __ALIGNED(4) XMC_ETH_MAC_DMA_DESC_t rx_desc[XMC_ETH_MAC_NUM_RX_BUF];
static __ALIGNED(4) XMC_ETH_MAC_DMA_DESC_t tx_desc[XMC_ETH_MAC_NUM_TX_BUF];
static __ALIGNED(4) uint8_t rx_buf[XMC_ETH_MAC_NUM_RX_BUF][XMC_ETH_MAC_BUF_SIZE];
static __ALIGNED(4) uint8_t tx_buf[XMC_ETH_MAC_NUM_TX_BUF][XMC_ETH_MAC_BUF_SIZE];

static ETHIF_t ethif =
{
  .phy_addr = 0,
  .mac =
  {
    .regs = ETH0,
    .rx_desc = rx_desc,
    .tx_desc = tx_desc,
    .rx_buf = &rx_buf[0][0],
    .tx_buf = &tx_buf[0][0],
    .num_rx_buf = XMC_ETH_MAC_NUM_RX_BUF,
    .num_tx_buf = XMC_ETH_MAC_NUM_TX_BUF
  },
  .phy =
  {
    .interface = XMC_ETH_LINK_INTERFACE_RMII,
    .enable_auto_negotiate = true,
  }
};

static struct netif xnetif = 
{
  /* set MAC hardware address length */
  .hwaddr_len = (u8_t)ETHARP_HWADDR_LEN,

  /* set MAC hardware address */
  .hwaddr =  {(u8_t)MAC_ADDR0, (u8_t)MAC_ADDR1,
              (u8_t)MAC_ADDR2, (u8_t)MAC_ADDR3,
              (u8_t)MAC_ADDR4, (u8_t)MAC_ADDR5},

  /* maximum transfer unit */
  .mtu = 1500U,
};

void _eth0_0_isr(void) {
    vosEnterIsr();
    vosSysLockIsr();
    XMC_ETH_MAC_ClearEventStatus(&ethif.mac, XMC_ETH_MAC_EVENT_RECEIVE);
    vosSemSignalIsr(ethif.eth_rx_semaphore);
    vosSysUnlockIsr();
    vosExitIsr();
}

void xmc_init_eth() {
    sys_sem_new(&ethif.eth_rx_semaphore, 0);

    vosInstallHandler(ETH0_0_IRQn, _eth0_0_isr);
    vhalIrqEnable(ETH0_0_IRQn);
}

static void tcpip_init_done(void *arg) {
    vosEventSet((VEvent) arg);
}

C_NATIVE(xmc4eth_init) {
    NATIVE_UNWARN();

    RELEASE_GIL();
    xmc_init_eth();

    // eth_drv.error = ETH_DRV_NOERROR;
    eth_drv.linked_event = NULL;
    eth_drv.ip.addr = 0;
    eth_drv.mask.addr = 0;
    eth_drv.gw.addr = 0;

    /* init lwip */
    VEvent tcpip_init_event = vosEventCreate();
    vosEventClear(tcpip_init_event);

    tcpip_init( tcpip_init_done, (void*) tcpip_init_event );
    int32_t wait_res = vosEventWait(tcpip_init_event, TIME_U(1000, MILLIS));
    vosEventDestroy(tcpip_init_event);
    if (wait_res == VRES_TIMEOUT) {
        ACQUIRE_GIL();
        return ERR_IOERROR_EXC;
    }

    //setup Z sockets
    xmc4eth_api.socket = lwip_socket;
    xmc4eth_api.connect = lwip_connect;
    xmc4eth_api.setsockopt = lwip_setsockopt;
    xmc4eth_api.getsockopt = lwip_getsockopt;
    xmc4eth_api.send = lwip_send;
    xmc4eth_api.sendto = lwip_sendto;
    xmc4eth_api.write = lwip_write;
    xmc4eth_api.recv = lwip_recv;
    xmc4eth_api.recvfrom = lwip_recvfrom;
    xmc4eth_api.read = lwip_read;
    xmc4eth_api.close = lwip_close;
    xmc4eth_api.shutdown = lwip_shutdown;
    xmc4eth_api.bind = lwip_bind;
    xmc4eth_api.accept = lwip_accept;
    xmc4eth_api.listen = lwip_listen;
    xmc4eth_api.select = lwip_select;
    xmc4eth_api.fcntl = lwip_fcntl;
    xmc4eth_api.ioctl = lwip_ioctl;
    xmc4eth_api.getaddrinfo = lwip_getaddrinfo;
    xmc4eth_api.freeaddrinfo = lwip_freeaddrinfo;
    xmc4eth_api.inet_addr = ipaddr_addr;
    xmc4eth_api.inet_ntoa = ip4addr_ntoa;

    gzsock_init(&xmc4eth_api);
    ACQUIRE_GIL();

    *res = MAKE_NONE();
    return ERR_OK;
}

C_NATIVE(xmc4eth_set_link_info) {
    C_NATIVE_UNWARN();

    NetAddress ip;
    NetAddress mask;
    NetAddress gw;
    NetAddress dns;

    ip.ip = 0;
    mask.ip = 0;
    gw.ip = 0;
    dns.ip = 0;

    if (parse_py_args("nnnn", nargs, args,
            &ip,
            &mask,
            &gw,
            &dns)
        != 4)
        return ERR_TYPE_EXC;

    if (dns.ip == 0) {
        OAL_MAKE_IP(dns.ip, 8, 8, 8, 8);
    }
    if (mask.ip == 0) {
        OAL_MAKE_IP(mask.ip, 255, 255, 255, 255);
    }
    if (gw.ip == 0) {
        OAL_MAKE_IP(gw.ip, OAL_IP_AT(ip.ip, 0), OAL_IP_AT(ip.ip, 1), OAL_IP_AT(ip.ip, 2), 1);
    }

    eth_drv.ip.addr = ip.ip;
    eth_drv.gw.addr = gw.ip;
    eth_drv.dns.addr = dns.ip;
    eth_drv.mask.addr = mask.ip;

    if (ip.ip != 0) {
        eth_drv.has_link_info = 1;
    }
    else {
        eth_drv.has_link_info = 0;
    }

    *res = MAKE_NONE();
    return ERR_OK;
}

C_NATIVE(xmc4eth_link_info) {
    NATIVE_UNWARN();

    NetAddress addr;
    addr.port = 0;

    PTuple* tpl = psequence_new(PTUPLE, 5);

    addr.ip = eth_drv.ip.addr;
    PTUPLE_SET_ITEM(tpl, 0, netaddress_to_object(&addr));
    addr.ip = eth_drv.mask.addr;
    PTUPLE_SET_ITEM(tpl, 1, netaddress_to_object(&addr));
    addr.ip = eth_drv.gw.addr;
    PTUPLE_SET_ITEM(tpl, 2, netaddress_to_object(&addr));
    addr.ip = eth_drv.dns.addr;
    PTUPLE_SET_ITEM(tpl, 3, netaddress_to_object(&addr));

    PObject* mac = psequence_new(PBYTES, ETHARP_HWADDR_LEN);
    XMC_ETH_MAC_GetAddressEx(&ethif.mac , PSEQUENCE_BYTES(mac));

    PTUPLE_SET_ITEM(tpl, 4, mac);
    *res = tpl;

    return ERR_OK;
}

C_NATIVE(xmc4eth_link) {
    C_NATIVE_UNWARN();

    if (eth_drv.linked_event == NULL) {
        RELEASE_GIL();
        eth_drv.linked_event = vosEventCreate();
        vosEventClear(eth_drv.linked_event);

        if (netif_add(&xnetif, &eth_drv.ip, &eth_drv.mask, &eth_drv.gw,
                  &ethif, &ethernetif_init, &tcpip_input) == NULL) {
            ACQUIRE_GIL();
            return ERR_IOERROR_EXC;
        };
    }
    else {
        // netif must be added only once
        RELEASE_GIL();
    }

    int32_t wait_res = vosEventWait(eth_drv.linked_event, TIME_U(15000, MILLIS));
    vosEventClear(eth_drv.linked_event);
    if (wait_res == VRES_TIMEOUT) {
        ACQUIRE_GIL();
        return ERR_IOERROR_EXC;
    }
    ACQUIRE_GIL();

    return ERR_OK;
}

static uint8_t is_link_up() {
    uint8_t is_up = netif_is_link_up(&xnetif);
    if (!eth_drv.has_link_info) {
        // dhcp, check also if has address
        is_up = (is_up && eth_drv.ip.addr);
    }
    return is_up;
}

C_NATIVE(xmc4eth_is_linked) {
    C_NATIVE_UNWARN();

  RELEASE_GIL();
  uint8_t is_up = is_link_up();
  ACQUIRE_GIL();

  *res = (is_up ? (PBOOL_TRUE()) : (PBOOL_FALSE()));
  return ERR_OK;
}

C_NATIVE(xmc4eth_resolve) {
    C_NATIVE_UNWARN();

    uint8_t *url;
    uint32_t len;
    int32_t code;
    NetAddress addr;
    ip_addr_t ares;

    if (parse_py_args("s", nargs, args, &url, &len) != 1)
        return ERR_TYPE_EXC;

    addr.ip = 0;
    RELEASE_GIL();

    uint8_t *name = (uint8_t*) gc_malloc(len + 1);
    memcpy(name, url, len);
    name[len] = 0;

    code = netconn_gethostbyname(name, &ares);

    gc_free(name);
    ACQUIRE_GIL();

    if (code != ERR_OK)
        return ERR_IOERROR_EXC;

    addr.port = 0;
    addr.ip = ares.addr;
    *res = netaddress_to_object(&addr);

    return ERR_OK;
}

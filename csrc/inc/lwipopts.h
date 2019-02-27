#ifndef __LWIPOPTS_H__
#define __LWIPOPTS_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * TCPIP_THREAD_PRIO: The priority assigned to the main tcpip thread.
 * The priority value itself is platform-dependent, but is passed to
 * sys_thread_new() when the thread is created.
 */
#define TCPIP_THREAD_PRIO              (VOS_PRIO_HIGH)

#define LWIP_COMPAT_MUTEX              (1)

#define MEM_USE_POOLS (0)
#define MEMP_SEPARATE_POOLS             (0)

#define NO_SYS                  0
#define LWIP_SOCKET             1
#define LWIP_NETCONN            1
#define SYS_LIGHTWEIGHT_PROT    1

#define LWIP_NETIF_STATUS_CALLBACK  1
#define LWIP_NETIF_LINK_CALLBACK    1

#define ETH_PAD_SIZE            2

#define MEM_ALIGNMENT           4

#define TCPIP_MBOX_SIZE             8
#define DEFAULT_TCP_RECVMBOX_SIZE   8
#define DEFAULT_UDP_RECVMBOX_SIZE   8
#define DEFAULT_RAW_RECVMBOX_SIZE   8
#define DEFAULT_ACCEPTMBOX_SIZE     8

#define TCPIP_THREAD_STACKSIZE  1024
#define DEFAULT_THREAD_STACKSIZE 1024

#define MEM_SIZE                8 * 1024

#define PBUF_POOL_SIZE          8
#define PBUF_POOL_BUFSIZE       1536
#define MEMP_NUM_PBUF           8

#define LWIP_DHCP               1
#define LWIP_DNS                1
#define LWIP_UDP                1
#define LWIP_TCP                1

#define TCP_MSS                 1460
#define TCP_WND                 (4 * TCP_MSS)
#define TCP_SND_BUF             (4 * TCP_MSS)
#define TCP_SND_QUEUELEN        8

#define CHECKSUM_GEN_IP         0
#define CHECKSUM_GEN_UDP        0
#define CHECKSUM_GEN_TCP        0
#define CHECKSUM_GEN_ICMP       0
#define CHECKSUM_CHECK_IP       0
#define CHECKSUM_CHECK_UDP      0
#define CHECKSUM_CHECK_TCP      0

#define MEMP_NUM_SYS_TIMEOUT    (LWIP_TCP + IP_REASSEMBLY + LWIP_ARP + (2*LWIP_DHCP) + LWIP_AUTOIP + LWIP_IGMP + LWIP_DNS + (PPP_SUPPORT*6*MEMP_NUM_PPP_PCB) + (LWIP_IPV6 ? (1 + LWIP_IPV6_REASS + LWIP_IPV6_MLD) : 0) + 5)

#define LWIP_RAND()                    (vhalRngGenerate())

#define LWIP_DEBUG

// #define DHCP_DEBUG                     (LWIP_DBG_ON)
// #define DNS_DEBUG                      (LWIP_DBG_ON)
// #define UDP_DEBUG                      (LWIP_DBG_ON)

#if 0
#define MEM_DEBUG                      (LWIP_DBG_ON)
#define MEMP_DEBUG                     (LWIP_DBG_ON)
#define PBUF_DEBUG                     (LWIP_DBG_ON)
#define API_LIB_DEBUG                  (LWIP_DBG_ON)
#define API_MSG_DEBUG                  (LWIP_DBG_ON)
#define TCPIP_DEBUG                    (LWIP_DBG_ON)
#define NETIF_DEBUG                    (LWIP_DBG_ON)
#define SOCKETS_DEBUG                  (LWIP_DBG_ON)
#define DEMO_DEBUG                     (LWIP_DBG_ON)
#define IP_DEBUG                       (LWIP_DBG_ON)
#define IP_REASS_DEBUG                 (LWIP_DBG_ON)
#define RAW_DEBUG                      (LWIP_DBG_ON)
#define ICMP_DEBUG                     (LWIP_DBG_ON)
#define TCP_DEBUG                      (LWIP_DBG_ON)
#define TCP_INPUT_DEBUG                (LWIP_DBG_ON)
#define TCP_OUTPUT_DEBUG               (LWIP_DBG_ON)
#define TCP_RTO_DEBUG                  (LWIP_DBG_ON)
#define TCP_CWND_DEBUG                 (LWIP_DBG_ON)
#define TCP_WND_DEBUG                  (LWIP_DBG_ON)
#define TCP_FR_DEBUG                   (LWIP_DBG_ON)
#define TCP_QLEN_DEBUG                 (LWIP_DBG_ON)
#define TCP_RST_DEBUG                  (LWIP_DBG_ON)
#define PPP_DEBUG                      (LWIP_DBG_ON)
#define ETHARP_DEBUG                   (LWIP_DBG_ON)
#define IGMP_DEBUG                     (LWIP_DBG_ON)
#define INET_DEBUG                     (LWIP_DBG_ON)
#define SYS_DEBUG                      (LWIP_DBG_ON)
#define TIMERS_DEBUG                   (LWIP_DBG_ON)
#define SLIP_DEBUG                     (LWIP_DBG_ON)
#define AUTOIP_DEBUG                   (LWIP_DBG_ON)
#define SNMP_MSG_DEBUG                 (LWIP_DBG_ON)
#define SNMP_MIB_DEBUG                 (LWIP_DBG_ON)
#endif

#ifdef __cplusplus
}
#endif
#endif /* __LWIPOPTS_H__ */


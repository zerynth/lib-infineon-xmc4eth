# -*- coding: utf-8 -*-
# @Author: lorenzo
# @Date:   2019-01-10 09:51:38
# @Last Modified by:   l.rizzello
# @Last Modified time: 2019-02-26 15:14:00

"""
.. module:: xmc4eth

********************************
Infineon XMC4000 Ethernet Module
********************************

This module implements the Zerynth driver for the Infineon XMC4000 family Ethernet (i.e. XMC4700 Relax Kit).

This module supports SSL/TLS.

    """

@native_c("xmc4eth_init",
    [
        "csrc/eth_ifc.c",
        "csrc/lwip/src/core/def.c",
        "csrc/lwip/src/core/dns.c",
        "csrc/lwip/src/core/inet_chksum.c",
        "csrc/lwip/src/core/init.c",
        "csrc/lwip/src/core/ip.c",
        "csrc/lwip/src/core/mem.c",
        "csrc/lwip/src/core/memp.c",
        "csrc/lwip/src/core/pbuf.c",
        "csrc/lwip/src/core/stats.c",
        "csrc/lwip/src/core/tcp.c",
        "csrc/lwip/src/core/tcp_out.c",
        "csrc/lwip/src/core/udp.c",
        "csrc/lwip/src/core/netif.c",
        "csrc/lwip/src/core/raw.c",
        "csrc/lwip/src/core/sys.c",
        "csrc/lwip/src/core/tcp_in.c",
        "csrc/lwip/src/core/timeouts.c",
        "csrc/lwip/src/core/ipv4/autoip.c",
        "csrc/lwip/src/core/ipv4/dhcp.c",
        "csrc/lwip/src/core/ipv4/etharp.c",
        "csrc/lwip/src/core/ipv4/icmp.c",
        "csrc/lwip/src/core/ipv4/igmp.c",
        "csrc/lwip/src/core/ipv4/ip4_addr.c",
        "csrc/lwip/src/core/ipv4/ip4.c",
        "csrc/lwip/src/core/ipv4/ip4_frag.c",
        "csrc/lwip/src/api/api_lib.c",
        "csrc/lwip/src/api/api_msg.c",
        "csrc/lwip/src/api/err.c",
        "csrc/lwip/src/api/netbuf.c",
        "csrc/lwip/src/api/netdb.c",
        "csrc/lwip/src/api/netifapi.c",
        "csrc/lwip/src/api/sockets.c",
        "csrc/lwip/src/api/tcpip.c",
        "csrc/lwip/src/netif/ethernet.c",
        "csrc/lwip/port/zerynth/netif/ethernetif.c",
        "csrc/lwip/port/zerynth/sys_arch.c",
        "csrc/ethernetif_init.c",
        "#csrc/misc/zstdlib.c",
        "#csrc/zsockets/*",
#-if ZERYNTH_SSL
        "#csrc/tls/mbedtls/library/*",
#-endif
    ],
    [
        "VHAL_ETH"
    ],
    [
        "-I.../csrc/inc",
        "-I.../csrc/lwip/src/include",
        "-I.../csrc/lwip/port/zerynth/include",
        "-I.../csrc/lwip/port/zerynth/netif",
        "-I#csrc/zsockets",
#-if ZERYNTH_SSL
        "-I#csrc/tls/mbedtls/include",
#-endif
    ]
)
def _hw_init():
    pass

def init():
    """
.. function:: init()

    Initializes the Ethernet chip connected to the device.
    """
    _hw_init()
    __builtins__.__default_net["eth"] = __module__
    __builtins__.__default_net["sock"][0] = __module__ #AF_INET
    __builtins__.__default_net["ssl"] = __module__

@native_c("xmc4eth_set_link_info", [])
def set_link_info(ip,mask,gw,dns):
    pass

@native_c("xmc4eth_link_info", [])
def link_info():
    pass

@native_c("xmc4eth_link", [])
def link():
    pass

@native_c("xmc4eth_is_linked",[],[])
def is_linked():
    pass

@native_c("xmc4eth_resolve", [])
def gethostbyname(hostname):
    pass

@native_c("xmc4eth_socket", [])
def socket(family,type,proto):
    pass

@native_c("xmc4eth_setsockopt", [])
def setsockopt(sock,level,optname,value):
    pass

@native_c("xmc4eth_close", [])
def close(sock):
    pass

@native_c("xmc4eth_connect", [])
def connect(sock,addr):
    pass

@native_c("xmc4eth_select",[])
def select(rlist,wist,xlist,timeout):
    pass

@native_c("xmc4eth_send", [])
def send(sock,buf,flags=0):
    pass

@native_c("xmc4eth_send_all", [])
def sendall(sock,buf,flags=0):
    pass

@native_c("xmc4eth_recv_into", [])
def recv_into(sock,buf,bufsize,flags=0,ofs=0):
    pass

#-if ZERYNTH_SSL
@native_c("xmc4eth_secure_socket", [], [])
def secure_socket(family, type, proto, ctx):
    pass
#-else
def secure_socket(family, type, proto, ctx):
    raise UnsupportedError
#-endif

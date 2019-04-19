/*
 * Copyright (c) 2006-2018, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2018-09-26     chenyong     first version
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>

#include <rtthread.h>
#ifdef SAL_USING_POSIX
#include <dfs_poll.h>
#endif

#include <wiz_socket.h>

#include <W5500/w5500.h>
#include <DNS/wizchip_dns.h>
#include <wizchip_socket.h>

#define DBG_ENABLE
#define DBG_SECTION_NAME               "wiz.socket"
#ifdef WIZ_DEBUG
#define DBG_LEVEL                      DBG_LOG
#else
#define DBG_LEVEL                      DBG_INFO
#endif /* WIZ_DEBUG */
#define DBG_COLOR
#include <rtdbg.h>

#ifndef WIZ_SOCKETS_NUM
#define WIZ_SOCKETS_NUM                8
#endif

#ifndef WIZ_DEF_LOCAL_PORT
#define WIZ_DEF_LOCAL_PORT             6000
#endif

extern rt_bool_t wiz_init_ok;
#define WIZ_INIT_STATUS_CHECK                                   \
    if (wiz_init_ok == RT_FALSE ||                              \
            (getPHYCFGR() & PHYCFGR_LNK_ON) != PHYCFGR_LNK_ON)  \
    {                                                           \
        return -1;                                              \
    }                                                           \

#define HTONS_PORT(x)                  ((((x) & 0x00ffUL) << 8) | (((x) & 0xff00UL) >> 8))
#define NIPQUAD(addr, index)           ((unsigned char *)&addr)[index]

typedef enum {
    WIZ_EVENT_SEND,
    WIZ_EVENT_RECV,
    WIZ_EVENT_ERROR,
} wiz_event_t;

/* the global array of available sockets */
static struct wiz_socket  sockets[WIZ_SOCKETS_NUM];
static uint16_t wiz_port = WIZ_DEF_LOCAL_PORT;

struct wiz_socket *wiz_get_socket(int socket)
{
    if (socket < 0 || socket >= WIZ_SOCKETS_NUM)
    {
        return RT_NULL;
    }

    /* check socket structure valid or not */
    if (sockets[socket].magic != WIZ_SOCKET_MAGIC)
    {
        return RT_NULL;
    }

    return &sockets[socket];
}

static void wiz_do_event_changes(struct wiz_socket *sock, wiz_event_t event, rt_bool_t is_plus)
{
    switch (event)
    {
    case WIZ_EVENT_SEND:
    {
        if (is_plus)
        {
            sock->sendevent = 1;

#ifdef SAL_USING_POSIX
            rt_wqueue_wakeup(&sock->wait_head, (void*) POLLOUT);
#endif
        }
        else if (sock->sendevent)
        {
            sock->sendevent = 0;
        }
        break;
    }
    case WIZ_EVENT_RECV:
    {
        if (is_plus)
        {
            sock->rcvevent++;

#ifdef SAL_USING_POSIX
            rt_wqueue_wakeup(&sock->wait_head, (void*) POLLIN);
#endif
        }
        else if (sock->rcvevent)
        {
            sock->rcvevent--;
        }
        break;
    }
    case WIZ_EVENT_ERROR:
    {
        if (is_plus)
        {
            sock->errevent++;

#ifdef SAL_USING_POSIX
            rt_wqueue_wakeup(&sock->wait_head, (void*) POLLERR);
#endif
        }
        else if (sock->errevent)
        {
            sock->errevent--;
        }
        break;
    }
    default:
        LOG_E("Not supported event (%d)", event);
    }
}

static void wiz_do_event_clean(struct wiz_socket *sock, wiz_event_t event)
{
    switch (event)
    {
    case WIZ_EVENT_SEND:
    {
        sock->sendevent = 0;
        break;
    }
    case WIZ_EVENT_RECV:
    {
        sock->rcvevent = 0;
        break;
    }
    case WIZ_EVENT_ERROR:
    {
        sock->errevent = 0;
        break;
    }
    default:
        LOG_E("Not supported event (%d)", event);
    }
}


int wiz_recv_notice_cb(int socket)
{
    struct wiz_socket *sock;

    sock = wiz_get_socket(socket);
    if (sock == RT_NULL)
    {
        return -1;
    }

    rt_sem_release(sock->recv_notice);

    wiz_do_event_changes(sock, WIZ_EVENT_RECV, RT_TRUE);

    return 0;
}

int wiz_closed_notice_cb(int socket)
{
    struct wiz_socket *sock;
    uint8_t socket_state = 0;

    sock = wiz_get_socket(socket);
    if (sock == RT_NULL)
    {
        return -1;
    }

    socket_state = getSn_SR(socket);
    if (socket_state != SOCK_CLOSE_WAIT)
    {
        return -1;
    }

    if (wizchip_close(socket) != SOCK_OK)
    {
        LOG_E("WIZnet socket(%d) close failed.", socket);
        return -1;
    }
    sock->state = SOCK_CLOSED;

    wiz_do_event_changes(sock, WIZ_EVENT_RECV, RT_TRUE);
    wiz_do_event_changes(sock, WIZ_EVENT_ERROR, RT_TRUE);

    rt_sem_release(sock->recv_notice);

    return 0;
}

static struct wiz_socket *alloc_socket(void)
{
    static rt_mutex_t wiz_slock = RT_NULL;
    struct wiz_socket *sock;
    char name[RT_NAME_MAX];
    int idx;

    if (wiz_slock == RT_NULL)
    {
        /* create WIZnet socket lock */
        wiz_slock = rt_mutex_create("w_lock", RT_IPC_FLAG_FIFO);
        if (wiz_slock == RT_NULL)
        {
            LOG_E("No memory for WIZnet socket lock!");
            return RT_NULL;
        }
    }

    rt_mutex_take(wiz_slock, RT_WAITING_FOREVER);

    /* find an empty WIZnet socket entry */
    for (idx = 0; idx < WIZ_SOCKETS_NUM && sockets[idx].magic; idx++);

    /* can't find an empty protocol family entry */
    if (idx == WIZ_SOCKETS_NUM)
    {
        goto __err;
    }

    sock = &(sockets[idx]);
    sock->magic = WIZ_SOCKET_MAGIC;
    sock->socket = idx;
    sock->state = SOCK_CLOSED;
    sock->server_addr = RT_NULL;
    sock->recv_timeout = 0;
    sock->send_timeout = 0;
    sock->rcvevent = 0;
    sock->sendevent = 0;
    sock->errevent = 0;

    rt_snprintf(name, RT_NAME_MAX, "%s%d", "wiz_sr", idx);
    /* create WIZnet socket receive mailbox */
    if ((sock->recv_notice = rt_sem_create(name, 0, RT_IPC_FLAG_FIFO)) == RT_NULL)
    {
        goto __err;
    }

    rt_snprintf(name, RT_NAME_MAX, "%s%d", "wiz_sr", idx);
    /* create WIZnet socket receive ring buffer lock */
    if ((sock->recv_lock = rt_mutex_create(name, RT_IPC_FLAG_FIFO)) == RT_NULL)
    {
        goto __err;
    }

    rt_mutex_release(wiz_slock);
    return sock;

__err:
    rt_mutex_release(wiz_slock);
    return RT_NULL;
}

int wiz_socket(int domain, int type, int protocol)
{
    struct wiz_socket *sock;
    uint8_t socket_type;
    uint8_t socket_state;

    /* check WIZnet initialize status */
    WIZ_INIT_STATUS_CHECK;

    /* check socket family protocol */
    RT_ASSERT(domain == 46 || domain == 2);

    switch (type)
    {
    case SOCK_STREAM:
        socket_type = Sn_MR_TCP;
        break;

    case SOCK_DGRAM:
        socket_type = Sn_MR_UDP;
        break;

    case SOCK_RAW:
        socket_type = Sn_MR_IPRAW;
        break;

    default:
        LOG_E("don't support socket type (%d)!", type);
        return -1;
    }

    /* allocate and initialize a new WIZnet socket */
    sock = alloc_socket();
    if (sock == RT_NULL)
    {
        LOG_E("allocate a new WIZnet socket failed!");
        return -1;
    }
    sock->type = socket_type;

#ifdef SAL_USING_POSIX
    rt_wqueue_init(&sock->wait_head);
#endif

    socket_state = getSn_SR(sock->socket);
    if (socket_state == SOCK_CLOSED)
    {
        switch(sock->type)
        {
        case Sn_MR_TCP:
            if (wizchip_socket(sock->socket, sock->type, wiz_port++, Sn_MR_ND) != sock->socket)
            {
                LOG_E("WIZnet TCP socket(%d) create failed!", sock->socket);
                rt_memset(sock, 0x00, sizeof(struct wiz_socket));
                return -1;
            }
            break;

        case Sn_MR_UDP:
        case Sn_MR_IPRAW:
            if (wizchip_socket(sock->socket, sock->type, wiz_port++, 0) != sock->socket)
            {
                LOG_E("WIZnet UDP socket(%d) create failed!", sock->socket);
                rt_memset(sock, 0x00, sizeof(struct wiz_socket));
                return -1;
            }
            break;

        default:
            LOG_E("Socket (%d) type %d is not support.", sock->socket, sock->type);
            return -1;
        }
    }
    else
    {
        rt_memset(sock, 0x00, sizeof(struct wiz_socket));
        return -1;
    }
    sock->state = SOCK_INIT;

    return sock->socket;
}

static int free_socket(struct wiz_socket *sock)
{
    if (sock->recv_notice)
    {
        rt_sem_delete(sock->recv_notice);
    }

    if (sock->recv_lock)
    {
        rt_mutex_delete(sock->recv_lock);
    }

    if (sock->server_addr)
    {
        rt_free(sock->server_addr);
    }

    rt_memset(sock, 0x00, sizeof(struct wiz_socket));

    return 0;
}

int wiz_closesocket(int socket)
{
    struct wiz_socket *sock;
    uint8_t socket_state;

    /* check WIZnet initialize status */
    WIZ_INIT_STATUS_CHECK;

    sock = wiz_get_socket(socket);
    if(sock == RT_NULL)
    {
        return -1;
    }

    socket_state = getSn_SR(socket);
    if (socket_state == SOCK_CLOSED)
    {
        free_socket(sock);
        return -1;
    }

    if (wizchip_close(socket) != SOCK_OK)
    {
        LOG_E("WIZnet socket(%d) close failed.", socket);
        free_socket(sock);
        return -1;
    }

    return free_socket(sock);
}

int wiz_shutdown(int socket, int how)
{
    struct wiz_socket *sock;
    uint8_t socket_state;

    /* check WIZnet initialize status */
    WIZ_INIT_STATUS_CHECK;

    sock = wiz_get_socket(socket);
    if (sock == RT_NULL)
    {
        return -1;
    }

    socket_state = getSn_SR(socket);
    if (socket_state == SOCK_CLOSED)
    {
        free_socket(sock);
        return -1;
    }

    if (wizchip_close(socket) != SOCK_OK)
    {
        LOG_E("WIZnet socket(%d) shutdown failed.", socket);
        free_socket(sock);
        return -1;
    }

    return free_socket(sock);
}

/* get IP address and port by socketaddr structure information */
static int socketaddr_to_ipaddr_port(const struct sockaddr *sockaddr, ip_addr_t *addr, uint16_t *port)
{
    const struct sockaddr_in* sin = (const struct sockaddr_in*) (const void *) sockaddr;
    
#if NETDEV_IPV4 && NETDEV_IPV6
    (*addr).u_addr.ip4.addr = sin->sin_addr.s_addr;
#elif NETDEV_IPV4
    (*addr).addr = sin->sin_addr.s_addr;
#elif NETDEV_IPV6
    LOG_E("not support IPV6.");
#endif /* NETDEV_IPV4 && NETDEV_IPV6 */

    *port = (uint16_t) HTONS_PORT(sin->sin_port);

    return 0;
}

/* ipaddr structure change to IP address */
static int ipaddr_to_ipstr(const struct sockaddr *sockaddr, uint8_t *ipstr)
{
    struct sockaddr_in *sin = (struct sockaddr_in *) sockaddr;

    /* change network ip_addr to ip string  */
    ipstr[0] = NIPQUAD(sin->sin_addr.s_addr, 0);
    ipstr[1] = NIPQUAD(sin->sin_addr.s_addr, 1);
    ipstr[2] = NIPQUAD(sin->sin_addr.s_addr, 2);
    ipstr[3] = NIPQUAD(sin->sin_addr.s_addr, 3);

    return 0;
}

int wiz_connect(int socket, const struct sockaddr *name, socklen_t namelen)
{
    struct wiz_socket *sock;
    ip_addr_t remote_addr;
    uint16_t remote_port;
    uint8_t socket_state;
    uint8_t ipstr[4] = { 0 };
    int result = 0;

    /* check WIZnet initialize status */
    WIZ_INIT_STATUS_CHECK;

    sock = wiz_get_socket(socket);
    if (sock == RT_NULL)
    {
        return -1;
    }

    socket_state = getSn_SR(socket);
    if (socket_state == SOCK_UDP || socket_state == SOCK_IPRAW)
    {
        if(sock->server_addr == RT_NULL)
        {
            sock->server_addr = rt_calloc(1, sizeof(struct sockaddr));
            if (sock->server_addr == RT_NULL)
            {
                LOG_E("no memory for structure sockaddr.");
                return -1;
            }
        }
        sock->server_addr->sa_len = name->sa_len;
        sock->server_addr->sa_family = name->sa_family;
        rt_memcpy(sock->server_addr->sa_data, name->sa_data, 14);

        return 0;
    }
    else if (socket_state != SOCK_INIT)
    {
        LOG_E("WIZnet connect failed, get socket(%d) register state(%d) error.", socket, socket_state);
        result = -1;
        goto __exit;
    }

    /* get IP address and port by socketaddr structure */
    socketaddr_to_ipaddr_port(name, &remote_addr, &remote_port);
    ipaddr_to_ipstr(name, ipstr);

    if (wizchip_connect(socket, ipstr, remote_port) != SOCK_OK)
    {
        LOG_E("WIZnet socket(%d) connect failed.", socket);
        result = -1;
        goto __exit;
    }
    sock->state = SOCK_ESTABLISHED;

__exit:
    if (result < 0)
    {
        wiz_do_event_changes(sock, WIZ_EVENT_ERROR, RT_TRUE);
    }
    else
    {
        wiz_do_event_changes(sock, WIZ_EVENT_SEND, RT_TRUE);
    }

    return result;
}

int wiz_sendto(int socket, const void *data, size_t size, int flags, const struct sockaddr *to, socklen_t tolen)
{
    struct wiz_socket *sock;
    uint8_t socket_state;
    int32_t send_len = 0;

    /* check WIZnet initialize status */
    WIZ_INIT_STATUS_CHECK;

    if (data == RT_NULL || size == 0)
    {
        LOG_E("WIZnet sendto input data or size error!");
        return -1;
    }

    sock = wiz_get_socket(socket);
    if (sock == RT_NULL)
    {
        return -1;
    }

    socket_state = getSn_SR(socket);
    switch (sock->type)
    {
    case Sn_MR_TCP:
    {
        if (socket_state == SOCK_CLOSED)
        {
            return 0;
        }
        else if (socket_state != SOCK_ESTABLISHED)
        {
            LOG_E("WIZnet send failed, get socket(%d) register state(%d) error.", socket, socket_state);
            return -1;
        }

        if ((send_len = wizchip_send(socket, (uint8_t *) data, size)) < 0)
        {
            LOG_E("WIZnet socket(%d) send data failed(%d).", socket, send_len);
            return -1;
        }
        break;
    }

    case Sn_MR_UDP:
    case Sn_MR_IPRAW:
    {
        ip_addr_t remote_addr;
        uint16_t remote_port = 0;
        uint8_t ipstr[4] = { 0 };

        if (socket_state != SOCK_UDP && socket_state != SOCK_IPRAW)
        {
            LOG_E("WIZnet sendto failed, get socket(%d) register state(%d) error.", socket, socket_state);
            return -1;
        }

        if (to)
        {
            socketaddr_to_ipaddr_port(to, &remote_addr, &remote_port);
            ipaddr_to_ipstr(to, ipstr);
        }
        else if (sock->server_addr)
        {
            socketaddr_to_ipaddr_port(sock->server_addr, &remote_addr, &remote_port);
            ipaddr_to_ipstr(sock->server_addr, ipstr);
        }

        if ((send_len = wizchip_sendto(socket, (uint8_t *) data, size, ipstr, remote_port)) < 0)
        {
            LOG_E("WIZnet socket(%d) send data failed(%d).", socket, send_len);
            return -1;
        }
        break;
    }

    default:
        LOG_E("WIZnet socket (%d) type %d is not support.", socket, sock->type);
        return -1;
    }

    return send_len;
}

int wiz_send(int socket, const void *data, size_t size, int flags)
{
    return wiz_sendto(socket, data, size, flags, RT_NULL, 0);
}

int wiz_recvfrom(int socket, void *mem, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen)
{
    struct wiz_socket *sock;
    uint8_t socket_state = 0;
    int32_t recv_len = 0, timeout = 0;
    int result = 0;

    /* check WIZnet initialize status */
    WIZ_INIT_STATUS_CHECK;

    if (mem == RT_NULL || len == 0)
    {
        LOG_E("WIZnet recvfrom input data or length error!");
        return -1;
    }

    sock = wiz_get_socket(socket);
    if (sock == RT_NULL)
    {
        return -1;
    }
    
    /* non-blocking sockets receive data */
    if (flags & MSG_DONTWAIT)
    {
        timeout = RT_WAITING_NO;
    }
    else if ((timeout = sock->recv_timeout) == 0)
    {
        /* set WIZNnet socket receive timeout */
        timeout = RT_WAITING_FOREVER;
    }

    socket_state = getSn_SR(socket);
    switch (sock->type)
    {
    case Sn_MR_TCP:
    {
        uint16_t recvsize = getSn_RX_RSR(socket);
        /* receive last transmission of remaining data */
        if(recvsize>0)
        {
            rt_mutex_take(sock->recv_lock, RT_WAITING_FOREVER);
            recv_len = wizchip_recv(socket, mem, len);
            if (recv_len > 0)
            {
                rt_mutex_release(sock->recv_lock);
                goto __exit;
            }
            rt_mutex_release(sock->recv_lock);
        }
        
        if (socket_state == SOCK_CLOSED)
        {
            return 0;
        }
        else if (socket_state != SOCK_ESTABLISHED)
        {
            LOG_E("WIZnet receive failed, get socket(%d) register state(%d) error.", socket, socket_state);
            result = -1;
            goto __exit;

        }

        while (1)
        {
            /* wait the receive semaphore */
            if (rt_sem_take(sock->recv_notice, timeout) < 0)
            {
                result = -1;
                /* blocking mode will prints an error and non-blocking mode exits directly */
                if ((flags & MSG_DONTWAIT) == 0)
                {
                    LOG_E("WIZnet socket (%d) receive timeout (%d)!", socket, timeout);
                    errno = EAGAIN;
                }
                goto __exit;
            }
            else
            {
                if (sock->state == SOCK_ESTABLISHED)
                {
                    /* get receive buffer to receiver ring buffer */
                    rt_mutex_take(sock->recv_lock, RT_WAITING_FOREVER);
                    recv_len = wizchip_recv(socket, mem, len);
                    if (recv_len < 0)
                    {
                        LOG_E("WIZnet socket(%d) receive data failed(%d).", socket, recv_len);
                        rt_mutex_release(sock->recv_lock);
                        result = -1;
                        goto __exit;
                    }
                    rt_mutex_release(sock->recv_lock);
                }
                else if (sock->state == SOCK_CLOSED)
                {
                    result = 0;
                    goto __exit;
                }
                break;
            }
        }
        break;
    }

    case Sn_MR_UDP:
    case Sn_MR_IPRAW:
    {
        ip_addr_t remote_addr;
        uint16_t remote_port = 0;
        uint8_t ipstr[4] = { 0 };
        uint16_t rx_len = 0;

        if (socket_state != SOCK_UDP && socket_state != SOCK_IPRAW)
        {
            LOG_E("WIZnet recvfrom failed, get socket(%d) register state(%d) error.", socket, socket_state);
            return -1;
        }

        if (from)
        {
            socketaddr_to_ipaddr_port(from, &remote_addr, &remote_port);
            ipaddr_to_ipstr(from, ipstr);
        }
        else if (sock->server_addr)
        {
            socketaddr_to_ipaddr_port(sock->server_addr, &remote_addr, &remote_port);
            ipaddr_to_ipstr(sock->server_addr, ipstr);
        }

        if (rt_sem_take(sock->recv_notice, timeout) < 0)
        {
            result = -1;
            /* blocking mode will prints an error and non-blocking mode exits directly */
            if ((flags & MSG_DONTWAIT) == 0)
            {
                LOG_E("WIZnet socket (%d) receive timeout (%d)!", socket, timeout);
            }
            goto __exit;
        }
        else
        {
            if ((rx_len = getSn_RX_RSR(socket)) > 0)
            {
                rx_len = rx_len > len ? len : rx_len;

                if((recv_len = wizchip_recvfrom(socket, mem, rx_len, ipstr, &remote_port)) < 0)
                {
                    LOG_E("WIZnet socket(%d) receive data failed(%d).", socket, recv_len);
                    result = -1;
                    goto __exit;
                }
            }
        }
        break;
    }

    default:
        LOG_E("WIZnet socket (%d) type %d is not support.", socket, sock->type);
        return -1;
    }


__exit:
    if (recv_len > 0)
    {
        errno = 0;
        result = recv_len;
        wiz_do_event_changes(sock, WIZ_EVENT_RECV, RT_FALSE);

        if (getSn_RX_RSR(socket) == 0)
        {
            wiz_do_event_clean(sock, WIZ_EVENT_RECV);
        }
    }
    else
    {
        wiz_do_event_changes(sock, WIZ_EVENT_ERROR, RT_TRUE);
    }

    return result;
}

int wiz_recv(int socket, void *mem, size_t len, int flags)
{
    return wiz_recvfrom(socket, mem, len, flags, RT_NULL, RT_NULL);
}

int wiz_getsockopt(int socket, int level, int optname, void *optval, socklen_t *optlen)
{
    struct wiz_socket *sock;
    int32_t timeout;

    /* check WIZnet initialize status */
    WIZ_INIT_STATUS_CHECK;

    if (optval == RT_NULL || optlen == RT_NULL)
    {
        LOG_E("WIZnet getsocketopt input option value or option length error.");
        return -1;
    }

    sock = wiz_get_socket(socket);
    if (sock == RT_NULL)
    {
        return -1;
    }

    switch (level)
    {
    case SOL_SOCKET:
    {
        switch (optname)
        {
        case SO_RCVTIMEO:
            timeout = sock->recv_timeout;
            ((struct timeval *)(optval))->tv_sec = (timeout) / 1000U;
            ((struct timeval *)(optval))->tv_usec = (timeout % 1000U) * 1000U;
            break;

        case SO_SNDTIMEO:
            timeout = sock->send_timeout;
            ((struct timeval *) optval)->tv_sec = timeout / 1000U;
            ((struct timeval *) optval)->tv_usec = (timeout % 1000U) * 1000U;
            break;

        default:
            LOG_E("WIZnet socket (%d) not support option name : %d.", socket, optname);
            return -1;
        }
        break;
    }

    default:
    {
        int8_t ret = 0;

        ret = wizchip_getsockopt(socket, (sockopt_type) level, optval);
        if (ret != SOCK_OK)
        {
            LOG_E("WIZnet getsocketopt input level(%d) error.", level);
            return ret;
        }
        break;
    }
    }

    return 0;
}
int wiz_setsockopt(int socket, int level, int optname, const void *optval, socklen_t optlen)
{
    struct wiz_socket *sock;

    /* check WIZnet initialize status */
    WIZ_INIT_STATUS_CHECK;

    if (optval == RT_NULL)
    {
        LOG_E("WIZnet setsockopt input option value or option length error.");
        return -1;
    }

    sock = wiz_get_socket(socket);
    if (sock == RT_NULL)
    {
        return -1;
    }

    switch (level)
    {
    case SOL_SOCKET:
    {
        switch (optname)
        {
        case SO_RCVTIMEO:
            sock->recv_timeout = ((const struct timeval *) optval)->tv_sec * 1000
                    + ((const struct timeval *) optval)->tv_usec / 1000;
            break;

        case SO_SNDTIMEO:
            sock->send_timeout = ((const struct timeval *) optval)->tv_sec * 1000
                    + ((const struct timeval *) optval)->tv_usec / 1000;
            break;

        default:
            LOG_E("WIZnet socket (%d) not support option name : %d.", socket, optname);
            return -1;
        }
        break;
    }

    case IPPROTO_TCP:
    {
        switch (optname)
        {
        case TCP_NODELAY:
            break;
        }
        break;
    }

    default:
    {
        int8_t ret = 0;

        ret = wizchip_setsockopt(socket, (sockopt_type) optname, (void *)optval);
        if (ret != SOCK_OK)
        {
            LOG_E("WIZnet getsocketopt input level(%d) error.", level);
            return ret;
        }
        break;
    }
    }

    return 0;
}

static uint32_t ipstr_atol(const char* nptr)
{
    uint32_t total = 0;
    char sign = '+';
    /* jump space */
    while (isspace(*nptr))
    {
        ++nptr;
    }

    if (*nptr == '-' || *nptr == '+')
    {
        sign = *nptr++;
    }

    while (isdigit(*nptr))
    {
        total = 10 * total + ((*nptr++) - '0');
    }
    return (sign == '-') ? -total : total;
}

/* IP address to unsigned int type */
static uint32_t ipstr_to_u32(char *ipstr)
{
    char ipBytes[4] = { 0 };
    uint32_t i;

    for (i = 0; i < 4; i++, ipstr++)
    {
        ipBytes[i] = (char) ipstr_atol(ipstr);
        if ((ipstr = strchr(ipstr, '.')) == RT_NULL)
        {
            break;
        }
    }
    return *(uint32_t *) ipBytes;
}

struct hostent *wiz_gethostbyname(const char *name)
{
    ip_addr_t addr;
    char ipstr[16] = { 0 };
    /* buffer variables for at_gethostbyname() */
    static struct hostent s_hostent;
    static char *s_aliases;
    static ip_addr_t s_hostent_addr;
    static ip_addr_t *s_phostent_addr[2];
    static char s_hostname[DNS_MAX_NAME_LENGTH + 1];
    size_t idx = 0;

    /* check WIZnet initialize status */
    if (wiz_init_ok == RT_FALSE ||
            (getPHYCFGR() & PHYCFGR_LNK_ON) != PHYCFGR_LNK_ON)
    {
        return RT_NULL;
    }

    if (name == RT_NULL)
    {
        LOG_E("WIZnet gethostbyname input name error!");
        return RT_NULL;
    }

    /* check domain name or IP address */
    for (idx = 0; idx < rt_strlen(name) && !isalpha(name[idx]); idx++);

    if (idx < rt_strlen(name))
    {
        int8_t ret = 0;
        uint8_t remote_ip[4] = { 0 };
        uint8_t dns_ip[4] = { 114, 114, 114, 114 };
        uint8_t data_buffer[512];

        for (idx = 0; idx < WIZ_SOCKETS_NUM && sockets[idx].magic; idx++);
        if (idx >= WIZ_SOCKETS_NUM)
        {
            LOG_E("WIZnet DNS failed, socket number is full.");
            return RT_NULL;
        }

        /* DNS client initialize */
        DNS_init(idx, data_buffer);
        /* DNS client processing */
        ret = DNS_run(dns_ip, (uint8_t *) name, remote_ip);
        if (ret == -1)
        {
            LOG_E("WIZnet MAX_DOMAIN_NAME is too small, should be redefined it.");
            return RT_NULL;
        }
        else if (ret < 0)
        {
            return RT_NULL;
        }

        /* domain resolve failed */
        if (remote_ip[0] == 0)
        {
            return RT_NULL;
        }

        rt_snprintf(ipstr, 16, "%u.%u.%u.%u", remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3]);
    }
    else
    {
        /* input name is IP address */
        rt_strncpy(ipstr, name, rt_strlen(name));
    }

#if NETDEV_IPV4 && NETDEV_IPV6
    addr.u_addr.ip4.addr = ipstr_to_u32(ipstr);
#elif NETDEV_IPV4
    addr.addr = ipstr_to_u32(ipstr);
#elif NETDEV_IPV6
    LOG_E("not support IPV6.");
#endif /* NETDEV_IPV4 && NETDEV_IPV6 */

    /* fill hostent structure */
    s_hostent_addr = addr;
    s_phostent_addr[0] = &s_hostent_addr;
    s_phostent_addr[1] = RT_NULL;
    rt_strncpy(s_hostname, name, DNS_MAX_NAME_LENGTH);
    s_hostname[DNS_MAX_NAME_LENGTH] = 0;
    s_hostent.h_name = s_hostname;
    s_aliases = RT_NULL;
    s_hostent.h_aliases = &s_aliases;
    s_hostent.h_addrtype = AF_WIZ;
    s_hostent.h_length = sizeof(ip_addr_t);
    s_hostent.h_addr_list = (char**) &s_phostent_addr;

    return &s_hostent;
}

int wiz_getaddrinfo(const char *nodename, const char *servname, const struct addrinfo *hints, struct addrinfo **res)
{
    int port_nr = 0;
    ip_addr_t addr;
    struct addrinfo *ai;
    struct sockaddr_storage *sa;
    size_t total_size = 0;
    size_t namelen = 0;
    int ai_family = 0;

    /* check WIZnet initialize status */
    if (wiz_init_ok == RT_FALSE ||
            (getPHYCFGR() & PHYCFGR_LNK_ON) != PHYCFGR_LNK_ON)
    {
        return EAI_FAIL;
    }

    if (res == RT_NULL)
    {
        return EAI_FAIL;
    }
    *res = RT_NULL;

    if ((nodename == RT_NULL) && (servname == RT_NULL))
    {
        return EAI_NONAME;
    }

    if (hints != RT_NULL)
    {
        ai_family = hints->ai_family;
        if (hints->ai_family != AF_WIZ && hints->ai_family != AF_INET && hints->ai_family != AF_UNSPEC)
        {
            return EAI_FAMILY;
        }
    }

    if (servname != RT_NULL)
    {
        /* service name specified: convert to port number */
        port_nr = atoi(servname);
        if ((port_nr <= 0) || (port_nr > 0xffff))
        {
            return EAI_SERVICE;
        }
    }

    if (nodename != RT_NULL)
    {
        /* service location specified, try to resolve */
        if ((hints != RT_NULL) && (hints->ai_flags & AI_NUMERICHOST))
        {
            /* no DNS lookup, just parse for an address string */
            if (!inet_aton(nodename, (ip4_addr_t * )&addr))
            {
                return EAI_NONAME;
            }

            if (ai_family == AF_WIZ || ai_family == AF_INET)
            {
                return EAI_NONAME;
            }
        }
        else
        {
            char ipstr[16] = { 0 };
            size_t idx = 0;

            /* check domain name or IP address */
            for (idx = 0; idx < rt_strlen(nodename) && !isalpha(nodename[idx]); idx++);

            if(idx < rt_strlen(nodename))
            {
                int8_t ret;
                uint8_t remote_ip[4] = { 0 };
                uint8_t dns_ip[4] = { 114, 114, 114, 114 };
                uint8_t data_buffer[512];

                for (idx = 0; idx < WIZ_SOCKETS_NUM && sockets[idx].magic; idx++);
                if (idx >= WIZ_SOCKETS_NUM)
                {
                    LOG_E("wizenet getaddrinfo failed, socket number is full.");
                    return EAI_FAIL;
                }

                /* DNS client initialize */
                DNS_init(idx, data_buffer);
                /* DNS client processing */
                ret = DNS_run(dns_ip, (uint8_t *) nodename, remote_ip);
                if (ret == -1)
                {
                    LOG_E("WIZnet MAX_DOMAIN_NAME is too small, should be redefined it.");
                    return EAI_FAIL;
                }
                else if (ret < 0)
                {
                    LOG_E("WIZnet getaddrinfo failed(%d).", ret);
                    return EAI_FAIL;
                }

                /* domain resolve failed */
                if (remote_ip[0] == 0)
                {
                    return EAI_FAIL;
                }

                rt_snprintf(ipstr, 16, "%u.%u.%u.%u", remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3]);
            }
            else
            {
                /* input name is IP address */
                rt_strncpy(ipstr, nodename, rt_strlen(nodename));
            }

        #if NETDEV_IPV4 && NETDEV_IPV6 
            addr.type = IPADDR_TYPE_V4;
            if ((addr.u_addr.ip4.addr = ipstr_to_u32(ip_str)) == 0)
            {
                return EAI_FAIL;
            }
        #elif NETDEV_IPV4
            addr.addr = ipstr_to_u32(ipstr);
        #elif NETDEV_IPV6
            LOG_E("not support IPV6."); 
        #endif /* NETDEV_IPV4 && NETDEV_IPV6 */
        }
    }
    else
    {
        /* to do service location specified, use loopback address */
    }

    total_size = sizeof(struct addrinfo) + sizeof(struct sockaddr_storage);
    if (nodename != RT_NULL)
    {
        namelen = rt_strlen(nodename);
        if (namelen > DNS_MAX_NAME_LENGTH)
        {
            /* invalid name length */
            return EAI_FAIL;
        }
        RT_ASSERT(total_size + namelen + 1 > total_size);
        total_size += namelen + 1;
    }
    /* If this fails, please report to lwip-devel! :-) */
    RT_ASSERT(total_size <= sizeof(struct addrinfo) + sizeof(struct sockaddr_storage) + DNS_MAX_NAME_LENGTH + 1);
    ai = (struct addrinfo *) rt_malloc(total_size);
    if (ai == RT_NULL)
    {
        return EAI_MEMORY;
    }
    rt_memset(ai, 0, total_size);
    /* cast through void* to get rid of alignment warnings */
    sa = (struct sockaddr_storage *) (void *) ((uint8_t *) ai + sizeof(struct addrinfo));
    struct sockaddr_in *sa4 = (struct sockaddr_in *) sa;
    /* set up sockaddr */
#if NETDEV_IPV4 && NETDEV_IPV6
    sa4->sin_addr.s_addr = addr.u_addr.ip4.addr;
#elif NETDEV_IPV4
    sa4->sin_addr.s_addr = addr.addr;
#elif NETDEV_IPV6
    LOG_E("not support IPV6."); 
#endif /* NETDEV_IPV4 && NETDEV_IPV6 */
    sa4->sin_family = AF_INET;
    sa4->sin_len = sizeof(struct sockaddr_in);
    sa4->sin_port = htons((uint16_t )port_nr);
    ai->ai_family = AF_INET;

    /* set up addrinfo */
    if (hints != RT_NULL)
    {
        /* copy socktype & protocol from hints if specified */
        ai->ai_socktype = hints->ai_socktype;
        ai->ai_protocol = hints->ai_protocol;
    }
    if (nodename != RT_NULL)
    {
        /* copy nodename to canonname if specified */
        ai->ai_canonname = ((char *) ai + sizeof(struct addrinfo) + sizeof(struct sockaddr_storage));
        rt_memcpy(ai->ai_canonname, nodename, namelen);
        ai->ai_canonname[namelen] = 0;
    }
    ai->ai_addrlen = sizeof(struct sockaddr_storage);
    ai->ai_addr = (struct sockaddr *) sa;

    *res = ai;

    return 0;
}

void wiz_freeaddrinfo(struct addrinfo *ai)
{
    struct addrinfo *next;

    /* check WIZnet initialize status */
    if (wiz_init_ok == RT_FALSE ||
            (getPHYCFGR() & PHYCFGR_LNK_ON) != PHYCFGR_LNK_ON)
    {
        return;
    }

    while (ai != NULL)
    {
        next = ai->ai_next;
        rt_free(ai);
        ai = next;
    }
}

/*
 * Copyright (c) 2006-2018, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2018-09-26     chenyong     first version
 */

#include <rtthread.h>
#include <rthw.h>

#include <netdb.h>
#include <sal.h>

#include <wiz.h>
#include <wiz_socket.h>

#ifdef SAL_USING_POSIX
#include <dfs_poll.h>
#endif

#ifdef SAL_USING_POSIX
static int wiz_poll(struct dfs_fd *file, struct rt_pollreq *req)
{
    int mask = 0;
    struct wiz_socket *sock;
    struct sal_socket *sal_sock;

    sal_sock = sal_get_socket((int) file->data);
    if(!sal_sock)
    {
        return -1;
    }

    sock = wiz_get_socket((int)sal_sock->user_data);
    if (sock != NULL)
    {
        rt_base_t level;

        rt_poll_add(&sock->wait_head, req);

        level = rt_hw_interrupt_disable();
        if (sock->rcvevent)
        {
            mask |= POLLIN;
        }
        if (sock->sendevent)
        {
            mask |= POLLOUT;
        }
        if (sock->errevent)
        {
            mask |= POLLERR;
        }
        rt_hw_interrupt_enable(level);
    }

    return mask;
}
#endif

static const struct proto_ops wiz_inet_stream_ops =
{
    wiz_socket,
    wiz_closesocket,
    NULL,
    NULL,
    wiz_connect,
    NULL,
    wiz_sendto,
    wiz_recvfrom,
    wiz_getsockopt,
    wiz_setsockopt,
    wiz_shutdown,
    NULL,
    NULL,
    NULL,

#ifdef SAL_USING_POSIX
    wiz_poll,
#endif /* SAL_USING_POSIX */
};

static int wiz_create(struct sal_socket *socket, int type, int protocol)
{
    RT_ASSERT(socket);

    //TODO Check type & protocol

    socket->ops = &wiz_inet_stream_ops;

    return 0;
}

static const struct proto_family wiz_inet_family_ops = {
    "wiz",
    AF_WIZ,
    AF_INET,
    wiz_create,
    wiz_gethostbyname,
    NULL,
    wiz_freeaddrinfo,
    wiz_getaddrinfo,
};

int wiz_inet_init(void)
{
    sal_proto_family_register(&wiz_inet_family_ops);

    return 0;
}
INIT_COMPONENT_EXPORT(wiz_inet_init);

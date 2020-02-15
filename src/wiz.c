/*
 * Copyright (c) 2006-2018, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2018-09-26     chenyong     first version
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wiz.h>
#include <wiz_socket.h>

#include <W5500/w5500.h>
#ifdef WIZ_USING_DHCP
#include <DHCP/wizchip_dhcp.h>
#endif

#include <arpa/inet.h>
#include <netdev.h>

#if !defined(WIZ_SPI_DEVICE) || !defined(WIZ_RST_PIN) || !defined(WIZ_IRQ_PIN)
#error "please config SPI device name, reset pin and irq pin in menuconfig."
#endif

#define DBG_ENABLE
#define DBG_SECTION_NAME               "wiz"
#ifdef WIZ_DEBUG
#define DBG_LEVEL                      DBG_LOG
#else
#define DBG_LEVEL                      DBG_INFO
#endif /* WIZ_DEBUG */
#define DBG_COLOR
#include <rtdbg.h>

#define IMR_SENDOK                     0x10
#define IMR_TIMEOUT                    0x08
#define IMR_RECV                       0x04
#define IMR_DISCON                     0x02
#define IMR_CON                        0x01
#define WIZ_DEFAULT_MAC                "00-E0-81-DC-53-1A"

#define WIZ_ID_LEN                     6
static char wiz_netdev_name[WIZ_ID_LEN];

#define WIZ_DHCP_SOCKET				   7

extern struct rt_spi_device *wiz_device;
extern int wiz_device_init(const char *spi_dev_name, rt_base_t rst_pin, rt_base_t isr_pin);
extern int wiz_inet_init(void);
static int wiz_netdev_info_update(struct netdev *netdev);

rt_bool_t wiz_init_ok = RT_FALSE;
static wiz_NetInfo wiz_net_info;
static rt_timer_t  dns_tick_timer;
static rt_timer_t  dhcp_timer;

static void spi_write_byte(uint8_t data)
{
    struct rt_spi_message spi_msg;

    rt_memset(&spi_msg, 0x00, sizeof(spi_msg));

    spi_msg.send_buf = &data;
    spi_msg.length = 1;

    rt_spi_transfer_message(wiz_device, &spi_msg);
}

static uint8_t spi_read_byte(void)
{
    struct rt_spi_message spi_msg;
    uint8_t data;

    rt_memset(&spi_msg, 0x00, sizeof(spi_msg));

    spi_msg.recv_buf = &data;
    spi_msg.length = 1;

    rt_spi_transfer_message(wiz_device, &spi_msg);

    return data;
}

static void spi_write_burst(uint8_t *pbuf, uint16_t len)
{
    struct rt_spi_message spi_msg;

    rt_memset(&spi_msg, 0x00, sizeof(spi_msg));

    spi_msg.send_buf = pbuf;
    spi_msg.length = len;

    rt_spi_transfer_message(wiz_device, &spi_msg);
}

static void spi_read_burst(uint8_t *pbuf, uint16_t len)
{
    struct rt_spi_message spi_msg;

    rt_memset(&spi_msg, 0x00, sizeof(spi_msg));

    spi_msg.recv_buf = pbuf;
    spi_msg.length = len;

    rt_spi_transfer_message(wiz_device, &spi_msg);
}

static void spi_cris_enter(void)
{
    rt_spi_take_bus(wiz_device);
}

static void spi_cris_exit(void)
{
    rt_spi_release_bus(wiz_device);
}

static void spi_cs_select(void)
{
    rt_spi_take(wiz_device);
}

static void spi_cs_deselect(void)
{
    rt_spi_release(wiz_device);
}

/* register TCP communication related callback function */
static int wiz_callback_register(void)
{
    /* register critical section callback function */
    reg_wizchip_cris_cbfunc(spi_cris_enter, spi_cris_exit);

#if (_WIZCHIP_IO_MODE_ == _WIZCHIP_IO_MODE_SPI_VDM_) || (_WIZCHIP_IO_MODE_ == _WIZCHIP_IO_MODE_SPI_FDM_)
    /* register SPI device CS select callback function */
    reg_wizchip_cs_cbfunc(spi_cs_select, spi_cs_deselect);
#else
#if (_WIZCHIP_IO_MODE_ & _WIZCHIP_IO_MODE_SIP_) != _WIZCHIP_IO_MODE_SIP_
#error "Unknown _WIZCHIP_IO_MODE_"
#else
    reg_wizchip_cs_cbfunc(wizchip_select, wizchip_deselect);
#endif
#endif
    /* register SPI device read/write data callback function */
    reg_wizchip_spi_cbfunc(spi_read_byte, spi_write_byte);
    reg_wizchip_spiburst_cbfunc(spi_read_burst, spi_write_burst);

    return RT_EOK;
}

/* initialize WIZnet chip configures */
static int wiz_chip_cfg_init(void)
{
#define    CW_INIT_MODE         2
#define    CW_INIT_SOCKETS      8
#define    CW_INIT_TIMEOUT      (2 * RT_TICK_PER_SECOND)

    rt_tick_t start_tick, now_tick;
    uint8_t phy_status;
    uint8_t memsize[CW_INIT_MODE][CW_INIT_SOCKETS] = { 0 };

    /* reset WIZnet chip internal PHY, configures PHY mode. */
    if (ctlwizchip(CW_INIT_WIZCHIP, (void*) memsize) == -1)
    {
        LOG_E("WIZCHIP initialize failed.");
        return -RT_ERROR;
    }

    start_tick = rt_tick_get();
    do
    {
        now_tick = rt_tick_get();
        if (now_tick - start_tick > CW_INIT_TIMEOUT)
        {
            LOG_E("WIZnet chip configure initialize timeout.");
            return -RT_ETIMEOUT;
        }

        /* waiting for link status online */
        if (ctlwizchip(CW_GET_PHYLINK, (void*) &phy_status) == -1)
        {
            LOG_E("Unknown PHY Link stauts.");
        }

        rt_thread_mdelay(100);
    } while (phy_status == PHY_LINK_OFF);

    return RT_EOK;
}

/* WIZnet chip hardware reset */
static void wiz_reset(void)
{
    rt_pin_write(WIZ_RST_PIN, PIN_LOW);
    rt_thread_mdelay(2);

    rt_pin_write(WIZ_RST_PIN, PIN_HIGH);
    rt_thread_mdelay(2);
}

#ifdef WIZ_USING_DHCP
static void wiz_ip_assign(void)
{
    /* get the assigned IP address and reconfigure the IP address of the chip */
    getIPfromDHCP(wiz_net_info.ip);
    getGWfromDHCP(wiz_net_info.gw);
    getSNfromDHCP(wiz_net_info.sn);
    getDNSfromDHCP(wiz_net_info.dns);
    wiz_net_info.dhcp = NETINFO_DHCP;

    ctlnetwork(CN_SET_NETINFO, (void*) &wiz_net_info);   
}

static void wiz_ip_conflict(void)
{
    /* deal with conflict IP for WIZnet DHCP  */
    LOG_D("conflict IP from DHCP.");
    RT_ASSERT(0);
}

static void wiz_dhcp_timer_entry(void *parameter)
{
    DHCP_time_handler();
}
#endif /* WIZ_USING_DHCP */

static int wiz_netstr_to_array(const char *net_str, uint8_t *net_array)
{
    int ret;
    unsigned int idx;

    RT_ASSERT(net_str);
    RT_ASSERT(net_array);

    if (strstr(net_str, "."))
    {
        int ip_addr[4];

        /* resolve IP address, gateway address or subnet mask */
        ret = sscanf(net_str, "%d.%d.%d.%d", ip_addr + 0, ip_addr + 1, ip_addr + 2, ip_addr + 3);
        if (ret != 4)
        {
            LOG_E("input address(%s) resolve error.", net_str);
            return -RT_ERROR;
        }

        for (idx = 0; idx < sizeof(ip_addr)/sizeof(ip_addr[0]); idx++)
        {
            net_array[idx] = ip_addr[idx];
        }
    }
    else
    {
        int mac_addr[6];

        /* resolve MAC address */
        if (strstr(net_str, ":"))
        {
            ret = sscanf(net_str, "%02x:%02x:%02x:%02x:%02x:%02x", mac_addr + 0, mac_addr + 1, mac_addr + 2,
                    mac_addr + 3,  mac_addr + 4,  mac_addr + 5);
        }
        else if (strstr(net_str, "-"))
        {
            ret = sscanf(net_str, "%02x-%02x-%02x-%02x-%02x-%02x", mac_addr + 0, mac_addr + 1, mac_addr + 2,
                    mac_addr + 3,  mac_addr + 4,  mac_addr + 5);
        }
        else
        {
            LOG_E("input MAC address(%s) format error.", net_str);
            return -RT_ERROR;
        }

        if (ret != 6)
        {
            LOG_E("input MAC address(%s) resolve error.", net_str);
            return -RT_ERROR;
        }

        for (idx = 0; idx < sizeof(mac_addr)/sizeof(mac_addr[0]); idx++)
        {
            net_array[idx] = mac_addr[idx];
        }
    }

    return RT_EOK;
}

/* set WIZnet device MAC address */
RT_WEAK void wiz_user_config_mac(char *mac_buf, rt_uint8_t buf_len)
{
	RT_ASSERT(mac_buf != RT_NULL);
	RT_ASSERT(buf_len > 0);
	
	rt_memset(mac_buf, 0x0, buf_len);
	rt_strncpy(mac_buf, WIZ_DEFAULT_MAC, buf_len);
}

static void wiz_set_mac(void)
{
	char mac_str[32];
	
	wiz_user_config_mac(mac_str, sizeof(mac_str));
	if (wiz_netstr_to_array(mac_str, wiz_net_info.mac) != RT_EOK)
	{
		wiz_netstr_to_array(WIZ_DEFAULT_MAC, wiz_net_info.mac);
	}
}

static int wiz_network_dhcp(struct netdev *netdev);

/* initialize WIZnet network configures */
static int wiz_network_init(rt_bool_t b_config)
{
    struct netdev * netdev;
    netdev = netdev_get_by_name(wiz_netdev_name);
    if (netdev == RT_NULL)
    {
        LOG_E("don`t find device(%s)", wiz_netdev_name);
        return -RT_ERROR;
    }

#ifndef WIZ_USING_DHCP
    if(wiz_netstr_to_array(WIZ_IPADDR, wiz_net_info.ip) != RT_EOK ||
            wiz_netstr_to_array(WIZ_MSKADDR, wiz_net_info.sn) != RT_EOK ||
                wiz_netstr_to_array(WIZ_GWADDR, wiz_net_info.gw) != RT_EOK)
    {
        netdev_low_level_set_status(netdev, RT_FALSE);
        netdev_low_level_set_link_status(netdev, RT_FALSE);
        return -RT_ERROR;
    }
    wiz_net_info.dhcp = NETINFO_STATIC;
#endif

	int result = RT_EOK;
	rt_bool_t b_status = b_config;
	
	/* set mac information */
	wiz_set_mac();
    /* set static WIZnet network information */
    ctlnetwork(CN_SET_NETINFO, (void*) &wiz_net_info);	

#ifdef WIZ_USING_DHCP
    /* alloc IP address through DHCP */
    {
        result = wiz_network_dhcp(netdev);
        if (result != RT_EOK)
        {
        	b_status = RT_FALSE;
            LOG_E("WIZnet network initialize failed, DHCP timeout.");			
        }
		else
		{
			b_status = RT_TRUE;
			LOG_D("WIZnet network initialize success.");	
		}
    }
#endif

    netdev_low_level_set_status(netdev, b_status);
    netdev_low_level_set_link_status(netdev, b_status);
    wiz_netdev_info_update(netdev);

    return result;
}

/* wizenet socket initialize */
static int wiz_socket_init(void)
{
    int idx = 0;

    /* socket(0-7) initialize */
    setSIMR(0xff);

    /* set socket receive/send buffer size */
    for (idx = 0; idx < WIZ_SOCKETS_NUM; idx++)
    {
        setSn_RXBUF_SIZE(idx, 0x02);
        setSn_TXBUF_SIZE(idx, 0x02);
    }

    /* set socket ISR state support */
    for (idx = 0; idx < WIZ_SOCKETS_NUM; idx++)
    {
        setSn_IMR(idx, (IMR_TIMEOUT | IMR_RECV | IMR_DISCON));
    }

    return RT_EOK;
}

static void wiz_dns_time_handler(void* arg)
{
    extern void DNS_time_handler(void);
    DNS_time_handler();
}

static int wiz_netdev_info_update(struct netdev *netdev)
{
    wiz_NetInfo net_info;

    ctlnetwork(CN_GET_NETINFO, (void *)&net_info);
    netdev_low_level_set_ipaddr(netdev, (const ip_addr_t *)&net_info.ip);
    netdev_low_level_set_gw(netdev, (const ip_addr_t *)&net_info.gw);
    netdev_low_level_set_netmask(netdev, (const ip_addr_t *)&net_info.sn);
    netdev_low_level_set_dns_server(netdev, 0, (const ip_addr_t *)&net_info.dns);
    memcpy(netdev->hwaddr, (const void *)&net_info.mac, netdev->hwaddr_len);
    /* 1 - Static, 2 - DHCP */
    netdev_low_level_set_dhcp_status(netdev, net_info.dhcp - 1);

    return RT_EOK;
}

static int wiz_netdev_set_up(struct netdev *netdev)
{
    netdev_low_level_set_status(netdev, RT_TRUE);
    return RT_EOK;
}

static int wiz_netdev_set_down(struct netdev *netdev)
{
    netdev_low_level_set_status(netdev, RT_FALSE);
    return RT_EOK;
}

static int wiz_netdev_set_addr_info(struct netdev *netdev, ip_addr_t *ip_addr, ip_addr_t *netmask, ip_addr_t *gw)
{
    rt_err_t result = RT_EOK;

    RT_ASSERT(netdev);
    RT_ASSERT(ip_addr || netmask || gw);

    ctlnetwork(CN_GET_NETINFO, (void *)&wiz_net_info);

    if (ip_addr)
        rt_memcpy(wiz_net_info.ip, &ip_addr->addr, sizeof(wiz_net_info.ip));

    if (netmask)
        rt_memcpy(wiz_net_info.sn, &netmask->addr, sizeof(wiz_net_info.sn));

    if (gw)
        rt_memcpy(wiz_net_info.gw, &gw->addr, sizeof(wiz_net_info.gw));

    if (ctlnetwork(CN_SET_NETINFO, (void *)&wiz_net_info) == RT_EOK)
    {
        if (ip_addr)
            netdev_low_level_set_ipaddr(netdev, ip_addr);

        if (netmask)
            netdev_low_level_set_netmask(netdev, netmask);

        if (gw)
            netdev_low_level_set_gw(netdev, gw);

        result = RT_EOK;
    }
    else
    {
        LOG_E("%s set addr info failed!", wiz_netdev_name);
        result = -RT_ERROR;
    }

    return result;
}

static int wiz_netdev_set_dns_server(struct netdev *netdev, uint8_t dns_num, ip_addr_t *dns_server)
{
    rt_err_t result = RT_EOK;

    RT_ASSERT(netdev);
    RT_ASSERT(dns_server);

    ctlnetwork(CN_GET_NETINFO, (void *)&wiz_net_info);

    rt_memcpy(wiz_net_info.dns, &dns_server->addr, sizeof(wiz_net_info.dns));

    if (ctlnetwork(CN_SET_NETINFO, (void *)&wiz_net_info) == RT_EOK)
    {
        netdev_low_level_set_dns_server(netdev, dns_num, (const ip_addr_t *)dns_server);
        result = RT_EOK;
    }
    else
    {
        LOG_E("%s set dns server failed!", wiz_netdev_name);
        result = -RT_ERROR;
    }

    return result;
}

static int wiz_netdev_set_dhcp(struct netdev *netdev, rt_bool_t is_enabled)
{
    rt_err_t result = RT_EOK;

    RT_ASSERT(netdev);

    ctlnetwork(CN_GET_NETINFO, (void *)&wiz_net_info);

    /* 1 - Static, 2 - DHCP */
    wiz_net_info.dhcp = (dhcp_mode)(is_enabled + 1);

    if (ctlnetwork(CN_SET_NETINFO, (void *)&wiz_net_info) == RT_EOK)
    {
        netdev_low_level_set_dhcp_status(netdev, is_enabled);
        result = RT_EOK;
    }
    else
    {
        LOG_E("%s set dhcp info failed!", wiz_netdev_name);
        result = -RT_ERROR;
    }

    return result;
}

static int wiz_netdev_ping(struct netdev *netdev, const char *host, size_t data_len, uint32_t timeout, struct netdev_ping_resp *ping_resp)
{
    RT_ASSERT(netdev);
    RT_ASSERT(host);
    RT_ASSERT(ping_resp);

    extern int wiz_ping(struct netdev *netdev, const char *host, size_t data_len, uint32_t times, struct netdev_ping_resp *ping_resp);

    return wiz_ping(netdev, host, data_len, timeout, ping_resp);
}

void wiz_netdev_netstat(struct netdev *netdev)
{
    // TODO
    return;
}

const struct netdev_ops wiz_netdev_ops =
{
    wiz_netdev_set_up,
    wiz_netdev_set_down,

    wiz_netdev_set_addr_info,
    wiz_netdev_set_dns_server,
    wiz_netdev_set_dhcp,

    wiz_netdev_ping,
    wiz_netdev_netstat,
};

static struct netdev *wiz_netdev_add(const char *netdev_name)
{
#define ETHERNET_MTU        1472
#define HWADDR_LEN          6
    struct netdev *netdev = RT_NULL;

    netdev = (struct netdev *)rt_calloc(1, sizeof(struct netdev));
    if (netdev == RT_NULL)
    {
        return RT_NULL;
    }

    netdev->flags = 0;
    netdev->mtu = ETHERNET_MTU;
    netdev->ops = &wiz_netdev_ops;
    netdev->hwaddr_len = HWADDR_LEN;

#ifdef PKG_USING_WIZNET
    extern int sal_wiz_netdev_set_pf_info(struct netdev *netdev);
    /* set the network interface socket/netdb operations */
    sal_wiz_netdev_set_pf_info(netdev);
#endif

    netdev_register(netdev, netdev_name, RT_NULL);

    return netdev;
}

#ifdef WIZ_USING_DHCP
static void wiz_dhcp_work(struct rt_work *dhcp_work, void *dhcp_work_data)
{
#define WIZ_DHCP_WORK_RETRY 		1
#define WIZ_DHCP_WORK_RETRY_TIME	(2 * RT_TICK_PER_SECOND)
	
	RT_ASSERT(dhcp_work_data != RT_NULL);

	struct netdev *netdev = (struct netdev *)dhcp_work_data;	
		
	uint8_t dhcp_times = 0;
	uint8_t data_buffer[1024];
	uint32_t dhcp_status = 0;
	
	rt_timer_start(dhcp_timer);
    DHCP_init(WIZ_DHCP_SOCKET, data_buffer);

	while (1)
    {
        /* DHCP start, return DHCP_IP_LEASED is success. */
        dhcp_status = DHCP_run();

        switch (dhcp_status)
        {
        case DHCP_IP_ASSIGN:
        case DHCP_IP_CHANGED:
        {            
        	/* to update netdev information */
    		wiz_netdev_info_update(netdev);
            break;
        }
        case DHCP_IP_LEASED:
        {
            DHCP_stop();
            rt_timer_stop(dhcp_timer);
			/* to update netdev information */
    		wiz_netdev_info_update(netdev);			
			if (dhcp_work)
			{
				/* according to leaset time, config next DHCP produce */
				rt_work_init(dhcp_work, wiz_dhcp_work, (void *)netdev);
	    		rt_work_submit(dhcp_work, (getDHCPLeasetime() - 60) * RT_TICK_PER_SECOND); 
			}
            return;
        }
        case DHCP_FAILED:
        {
            dhcp_times++;
            break;
        }
		case DHCP_STOPPED:
		{
			dhcp_times = WIZ_DHCP_WORK_RETRY;
			break;
		}
        default:
            break;
        }
		
        if (dhcp_times >= WIZ_DHCP_WORK_RETRY)
        {
            DHCP_stop();
            rt_timer_stop(dhcp_timer);

			if (dhcp_work)
			{
				/* according to WIZ_DHCP_WORK_RETRY_TIME, config reconfig after 2 secs */
				rt_work_init(dhcp_work, wiz_dhcp_work, (void *)netdev);
				rt_work_submit(dhcp_work, WIZ_DHCP_WORK_RETRY_TIME); 
			}
            break;
        }
    }
}

static int wiz_network_dhcp(struct netdev *netdev)
{
	if (netdev == RT_NULL)
		return -RT_EINVAL;
	
	/* set default MAC address for DHCP */
    setSHAR(wiz_net_info.mac);
    /* DHCP configure initialize, clear information other than MAC address */
    setSn_RXBUF_SIZE(WIZ_DHCP_SOCKET, 0x02);
    setSn_TXBUF_SIZE(WIZ_DHCP_SOCKET, 0x02);
	/* register to assign IP address and conflict callback */
    reg_dhcp_cbfunc(wiz_ip_assign, wiz_ip_assign, wiz_ip_conflict);

	dhcp_timer = rt_timer_create("wiz_dhcp", wiz_dhcp_timer_entry, RT_NULL, 1 * RT_TICK_PER_SECOND, RT_TIMER_FLAG_PERIODIC);
    if (dhcp_timer == RT_NULL)
        return -RT_ERROR;

	struct rt_work *dhcp_work = (struct rt_work *)rt_calloc(1, sizeof(struct rt_work));
	if (dhcp_work == RT_NULL)
		return -RT_ENOMEM;
	
	wiz_dhcp_work(dhcp_work, netdev);
	return RT_EOK;
}
#endif /* WIZ_USING_DHCP */

static void wiz_link_status_thread_entry(void *parameter)
{
#define WIZ_PHYCFGR_LINK_STATUS 0x01

    uint8_t phycfgr = 0;
    struct netdev *netdev = RT_NULL;

    netdev = netdev_get_by_name(wiz_netdev_name);
    if (netdev == RT_NULL)
    {
        LOG_E("don`t find device(%s)", wiz_netdev_name);
        return;
    }

    while (1)
    {
        /* Get PHYCFGR data */
        phycfgr = getPHYCFGR();

        /* If the register contents are different from the struct contents, the struct needs to be updated */
        if ((phycfgr & WIZ_PHYCFGR_LINK_STATUS) != ((netdev->flags & NETDEV_FLAG_LINK_UP) ? RT_TRUE : RT_FALSE))
        {
            if (phycfgr & WIZ_PHYCFGR_LINK_STATUS)
            {
#ifdef WIZ_USING_DHCP
				wiz_dhcp_work(RT_NULL, netdev);
#endif				
                netdev_low_level_set_link_status(netdev, phycfgr & WIZ_PHYCFGR_LINK_STATUS);
                wiz_netdev_info_update(netdev);
                LOG_I("%s netdev link status becomes link up", wiz_netdev_name);
            }
            else
            {
                netdev_low_level_set_link_status(netdev, phycfgr & WIZ_PHYCFGR_LINK_STATUS);
                LOG_I("%s netdev link status becomes link down", wiz_netdev_name);
            }
        }
        rt_thread_mdelay(1000);
    }
}

/* WIZnet initialize device and network */
int wiz_init(void)
{
    int result = RT_EOK;
    rt_bool_t b_config = RT_TRUE;
    rt_thread_t tid;

    if (wiz_init_ok == RT_TRUE)
    {
        LOG_I("RT-Thread WIZnet package is already initialized.");
        return RT_EOK;
    }

    /* WIZnet SPI device and pin initialize */
    result = wiz_device_init(WIZ_SPI_DEVICE, WIZ_RST_PIN, WIZ_IRQ_PIN);
    if (result != RT_EOK)
    {
        goto __exit;
    }

    /* Add wiz to the netdev list */
    ctlwizchip(CW_GET_ID, (void *)wiz_netdev_name);
    wiz_netdev_add(wiz_netdev_name);

    /* WIZnet SPI device reset */
    wiz_reset();
    /* set WIZnet device read/write data callback */
    wiz_callback_register();
    /* WIZnet chip configure initialize */	
    result = wiz_chip_cfg_init();
    if (result != RT_EOK)
    {
        b_config = RT_FALSE;
    }
    /* WIZnet network initialize */
    result = wiz_network_init(b_config);
    if (result != RT_EOK)
    {
        goto __exit;
    }
    /* WIZnet socket initialize */
    wiz_socket_init();

    dns_tick_timer = rt_timer_create("dns_tick", wiz_dns_time_handler, RT_NULL, 1*RT_TICK_PER_SECOND, RT_TIMER_FLAG_SOFT_TIMER|RT_TIMER_FLAG_PERIODIC);
    rt_timer_start(dns_tick_timer);

    /* create WIZnet link status Polling thread  */
    tid = rt_thread_create("wiz_stat", wiz_link_status_thread_entry, RT_NULL, 2048, RT_THREAD_PRIORITY_MAX - 4, 20);
    if (tid != RT_NULL)
    {
        rt_thread_startup(tid);
    }

__exit:
    if (result == RT_EOK)
    {
        wiz_init_ok = RT_TRUE;
        LOG_I("RT-Thread WIZnet package (V%s) initialize success.", WIZ_SW_VERSION);
    }
    else
    {
        LOG_E("RT-Thread WIZnet package (V%s) initialize failed(%d).", WIZ_SW_VERSION, result);
    }

    return result;
}
INIT_ENV_EXPORT(wiz_init);

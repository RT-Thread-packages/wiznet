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

#include <wiz.h>
#include <wiz_socket.h>
#include <W5500/w5500.h>

#define DBG_ENABLE
#define DBG_SECTION_NAME               "wiz.dev"
#ifdef WIZ_DEBUG
#define DBG_LEVEL                      DBG_LOG
#else
#define DBG_LEVEL                      DBG_INFO
#endif /* WIZ_DEBUG */
#define DBG_COLOR
#include <rtdbg.h>

extern int wiz_recv_notice_cb(int socket);
extern int wiz_closed_notice_cb(int socket);

static rt_mailbox_t wiz_rx_mb = RT_NULL;
struct rt_spi_device *wiz_device = RT_NULL;

static void wiz_isr(void)
{
    /* enter interrupt */
    rt_interrupt_enter();

    rt_mb_send(wiz_rx_mb, (rt_uint32_t) wiz_device);

    /* leave interrupt */
    rt_interrupt_leave();
}

static void wiz_data_thread_entry(void *parameter)
{
#define IR_SOCK(ch)         (0x01 << ch)   /**< check socket interrupt */

    struct rt_spi_device* dev;

    while (1)
    {
        if (rt_mb_recv(wiz_rx_mb, (rt_ubase_t*) &dev, RT_WAITING_FOREVER) == RT_EOK)
        {
            uint8_t ir, sir, sn_ir;
            int8_t socket = -1;

            /* get IR data than clean IR */
            ir = getIR();
            setIR(ir);

            if ((ir & IR_CONFLICT) == IR_CONFLICT)
            {
                setIR(IR_CONFLICT);
            }

            if ((ir & IR_UNREACH) == IR_UNREACH)
            {
                setIR(IR_UNREACH);
            }

            /* get and process socket interrupt register */
            sir = getSIR();

            for (socket = 0; socket < 8; socket++)
            {
                sn_ir = 0;

                if (sir & IR_SOCK(socket))
                {
                    /* save interrupt value*/
                    sn_ir = getSn_IR(socket);

                    if (sn_ir & Sn_IR_CON)
                    {
                        setSn_IR(socket, Sn_IR_CON);
                    }
                    if (sn_ir & Sn_IR_DISCON)
                    {
                        wiz_closed_notice_cb(socket);
                        setSn_IR(socket, Sn_IR_DISCON);
                    }
                    if (sn_ir & Sn_IR_RECV)
                    {
                        wiz_recv_notice_cb(socket);
                        setSn_IR(socket, Sn_IR_RECV);
                    }
                    if (sn_ir & Sn_IR_TIMEOUT)
                    {
                        setSn_IR(socket, Sn_IR_TIMEOUT);
                    }
                }
            }
        }
    }
}

static int wiz_spi_init(const char *spi_dev_name)
{
    rt_thread_t tid;

    RT_ASSERT(spi_dev_name);

    if (wiz_device != RT_NULL)
    {
        return 0;
    }

    wiz_device = (struct rt_spi_device *) rt_device_find(spi_dev_name);
    if (wiz_device == RT_NULL)
    {
        LOG_E("WIZnet SPI device %s not found!", spi_dev_name);
        return -RT_ENOSYS;
    }

    /* check SPI device type */
    RT_ASSERT(wiz_device->parent.type == RT_Device_Class_SPIDevice);

    /* configure SPI device*/
    {
        struct rt_spi_configuration cfg;
        cfg.data_width = 8;
        cfg.mode = RT_SPI_MASTER | RT_SPI_MODE_0 | RT_SPI_MSB;  /* SPI Compatible Modes 0 */
        cfg.max_hz = 40 * 1000 * 1000;                          /* SPI Interface with Clock Speeds Up to 40 MHz */
        rt_spi_configure(wiz_device, &cfg);
    }

    if (rt_device_open((rt_device_t) wiz_device, RT_DEVICE_OFLAG_RDWR) != RT_EOK)
    {
        LOG_E("open WIZnet SPI device %s error.", spi_dev_name);
        return -RT_ERROR;
    }

    /* initialize RX mailbox */
    wiz_rx_mb = rt_mb_create("wiz_mb", WIZ_RX_MBOX_NUM, RT_IPC_FLAG_FIFO);
    if (wiz_rx_mb == RT_NULL)
    {
        LOG_E("WIZnet create receive data mailbox error.");
        return -RT_ENOMEM;
    }

    /* create WIZnet SPI RX thread  */
    tid = rt_thread_create("wiz", wiz_data_thread_entry, RT_NULL, 512, RT_THREAD_PRIORITY_MAX / 6, 20);
    if (tid != RT_NULL)
    {
        rt_thread_startup(tid);
    }

    return RT_EOK;
}

int wiz_device_init(const char *spi_dev_name, rt_base_t rst_pin, rt_base_t isr_pin)
{
    int result = RT_EOK;

    /* WIZnet SPI device initialize */
    result = wiz_spi_init(spi_dev_name);
    if (result != RT_EOK)
    {
        LOG_E("WIZnet SPI device initialize failed.");
        return result;
    }

    /* initialize reset pin */
    rt_pin_mode(rst_pin, PIN_MODE_OUTPUT);

    /* initialize interrupt pin */
    rt_pin_mode(isr_pin, PIN_MODE_INPUT_PULLUP);
    rt_pin_attach_irq(isr_pin, PIN_IRQ_MODE_FALLING, (void (*)(void*)) wiz_isr, RT_NULL);
    rt_pin_irq_enable(isr_pin, PIN_IRQ_ENABLE);

    return RT_EOK;
}

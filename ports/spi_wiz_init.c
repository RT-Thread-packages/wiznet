/*
 * Copyright (c) 2006-2023, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2024-08-23     LiangZeHao    first version
 */

#include <rtthread.h>
#include "drv_spi.h"



#if defined(PKG_USING_WIZNET) && defined(WIZ_USING_SPI_ATTACH)

extern int rt_hw_spi_wiz_init(void);

int rt_hw_spi_wiz_init(void)
{
    rt_hw_spi_device_attach("spi1", WIZ_SPI_DEVICE, GPIOB, GPIO_PIN_6);

    return RT_EOK;
}

#endif

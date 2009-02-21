/*
 *  Homeplug 1.0/AV device definitions
 *
 *  Copyright (C) 2007-2008 Xavier Carcelle <xavier.carcelle@gmail.com>
 *		    	    Florian Fainelli <florian@openwrt.org>
 *			    Nicolas Thill <nico@openwrt.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __HPAV_DEVICE_H__
#define __HPAV_DEVICE_H__

#include <stdio.h>
#include "homeplug_av.h"

extern int dump_hex(void *buf, int len, char *sep);

/**
 * hpav_device - structure which contains useful device informations
 * @name:	name of the device
 * @macaddr:	MAC address of the device
 * @role:	role of the device in the HomePlug AV network
 * @sw_version:	version of the software running on it
 * @next:	pointer to a hpav_device structure
 */
struct hpav_device {
	char 		*name; 		/* Device name, if any */
	u_int8_t	macaddr[6];	/* MAC address of the device */
	enum sta_role	role;		/* Device role in the network */
	char		*sw_version;	/* Software version of the device */
	struct		hpav_device *next;
};

#endif /* __HPAV_DEVICE_H__ */

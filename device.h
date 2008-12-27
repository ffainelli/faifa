/*
 * HomePlug AV device definitions
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

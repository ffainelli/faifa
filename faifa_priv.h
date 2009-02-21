/*
 *  Faifa library private interface
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

#ifndef __FAIFA_PRIV_H__
#define __FAIFA_PRIV_H__

#include <net/if.h>
#include <pcap.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#ifndef UNUSED
# if defined(__GNUC__)
#  define UNUSED(x) UNUSED_ ## x __attribute__((unused))
# elif defined(__LCLINT__)
#  define UNUSED(x) /*@unused@*/ x
# else
#  define UNUSED(x) x
# endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct faifa {
	char ifname[IFNAMSIZ];
	pcap_t *pcap;
	char error[256];
};

extern void faifa_set_error(faifa_t *faifa, char *format, ...);

#ifdef __cplusplus
}
#endif

#endif /* __FAIFA_PRIV_H__ */

/*
 *  Faifa library compatibility layer
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

#ifndef __FAIFA_COMPAT_H__
#define __FAIFA_COMPAT_H__

#ifndef ETHERTYPE_8021Q
# define ETHERTYPE_8021Q  0x8100
#endif

#ifdef __CYGWIN__
#define ETH_ZLEN        60              /* Min. octets in frame w/o FCS */
#define ETH_ALEN	6
#define ETHER_CRC_LEN	4
#define ETH_FRAME_LEN   1514
#define ETHER_ADDR_LEN	ETH_ALEN
#define ETHER_MAX_LEN   (ETH_FRAME_LEN + ETHER_CRC_LEN) /* max packet length */

/* This is a name for the 48 bit ethernet address available on many
 *    systems.  */
struct ether_addr
{
  u_int8_t ether_addr_octet[ETH_ALEN];
} __attribute__ ((__packed__));

/* 10Mb/s ethernet header */
struct ether_header
{
	u_int8_t  ether_dhost[ETH_ALEN];      /* destination eth addr */
	u_int8_t  ether_shost[ETH_ALEN];      /* source ether addr    */
	u_int16_t ether_type;                 /* packet type ID field */
} __attribute__ ((__packed__));

#endif

#endif /* __FAIFA_COMPAT_H__ */

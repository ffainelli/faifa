/*
 * faifa_priv.h - faifa library private interface
 * 
 * Copyright (C) 2007-2008 
 *	Xavier Carcelle <xavier.carcelle@gmail.com>
 *	Florian Fainelli <florian@openwrt.org>
 *	Nicolas Thill <nico@openwrt.org>
 *
 * License:
 *	GPLv2
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

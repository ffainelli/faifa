/*
 * frame.h - frame operations public interface
 * 
 * Copyright (C) 2007-2008 
 *	Xavier Carcelle <xavier.carcelle@gmail.com>
 *	Florian Fainelli <florian@openwrt.org>
 *	Nicolas Thill <nico@openwrt.org>
 *
 * License:
 *	GPLv2
 */

int ether_init_header(void *buf, int len, u_int8_t *da, u_int8_t *sa, u_int16_t ethertype);

int set_init_callback(u_int16_t mmtype, int (*callback));

int set_dump_callback(u_int16_t mmtype, int (*callback));

void do_receive_frame(faifa_t *faifa, void *buf, int len, void *UNUSED(user));

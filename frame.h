/*
 *  Frame operations public interface
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

int ether_init_header(void *buf, int len, u_int8_t *da, u_int8_t *sa, u_int16_t ethertype);
int set_init_callback(u_int16_t mmtype, int (*callback));
int set_dump_callback(u_int16_t mmtype, int (*callback));
void do_receive_frame(faifa_t *faifa, void *buf, int len, void *UNUSED(user));

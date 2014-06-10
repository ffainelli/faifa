/*
 *  Faifa library public interface
 *
 *  Copyright (C) 2007-2008 Xavier Carcelle <xavier.carcelle@gmail.com>
 *		    	    Florian Fainelli <florian@openwrt.org>
 *			    Nicolas Thill <nico@openwrt.org>
 *
 *  The BSD License
 *  ===============
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *  3. Neither the name of OpenLink Software Inc. nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL OPENLINK OR
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#ifndef __FAIFA_H__
#define __FAIFA_H__

#include <sys/types.h>

#define FAIFA_VERSION_MAJOR 0
#define FAIFA_VERSION_MINOR 1

#define faifa_printf(stream, fmt,args...) \
	fprintf (stream, fmt ,##args) \

#ifdef __cplusplus
extern "C" {
#endif

/**
 * faifa_t - private handle
 */
typedef struct faifa faifa_t;

/**
 * faifa_init - init library
 * @return
 *	private handle on success, NULL on error
 */
extern faifa_t *faifa_init(void);

/**
 * faifa_free - free library
 * @faifa: private handle
 */
extern void faifa_free(faifa_t *faifa);

/**
 * faifa_error - return a text message related to the last error
 * @faifa: private handle
 * @return
 *	error message string
 */
extern char *faifa_error(faifa_t *faifa);

/**
 * faifa_open - open specified network device
 * @faifa: private handle
 * @name: network device name
 * @return
 *	0 on success, -1 on error
 */
extern int faifa_open(faifa_t *faifa, char *name);

/**
 * faifa_close - close network device
 * @faifa: private handle
 * @return
 *	0 on success, -1 on error
 */
extern int faifa_close(faifa_t *faifa);

/**
 * faifa_send - send raw ethernet frame
 * @faifa: private handle
 * @buf: data buffer
 * @len: data buffer length
 * @return
 *	number of bytes sent on success, -1 on error
 */
extern int faifa_send(faifa_t *faifa, void *buf, int len);

/**
 * faifa_recv - receive raw ethernet frame
 * @faifa: private handle
 * @buf: data buffer
 * @len: data buffer length
 * @return
 *	number of bytes received on success, -1 on error
 */
extern int faifa_recv(faifa_t *faifa, void *buf, int len);

/**
 * faifa_loop_handler_t - packet dispatch handler
 */
typedef void (*faifa_loop_handler_t)(faifa_t *faifa, void *buf, int len, void *user);

/**
 * faifa_loop - receive and dispatch frames in a loop
 * @faifa: private handle
 * @handler: frame dispatch handler
 * @user: user value passed to the dispatch handler
 * @return
 *	0 on success, -1 on error
 */
extern int faifa_loop(faifa_t *faifa, faifa_loop_handler_t handler, void *user);


extern int faifa_sprint_hex(char *str, void *buf, int len, char *sep);

/**
 * faifa_parse_mac_addr - parses a MAC address
 * @faifa: private handle
 * @mac: mac address as a string
 * @addr: mac address as a 6-bytes buffer
 * @return
 *	0 on success, -1 on error
 */
extern int faifa_parse_mac_addr(faifa_t *faifa, const char *mac, u_int8_t *addr);

/**
 * faifa_set_dst_addr - sets the destination MAC address
 * @faifa: private handle
 * @mac: destination MAC address
 *
 */
extern void faifa_set_dst_addr(faifa_t *faifa, const u_int8_t *addr);

/**
 * faifa_set_verbose - set the faifa verbosity
 * @faifa: private handle
 * @verbose: verbosity level
 */
extern void faifa_set_verbose(faifa_t *faifa, int verbose);

static inline int faifa_is_zero_ether_addr(const u_int8_t *addr)
{
	return !(addr[0] | addr[1] | addr[2] | addr[3] | addr[4] | addr[5]);
}

#ifdef __cplusplus
}
#endif

#endif /* __FAIFA_H__ */

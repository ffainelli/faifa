/*
 *  Cryptographic headers
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

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <sys/types.h>

#define MAX_SECRET_SIZ	64
#define SALT_SIZ	8

extern u_int8_t dak_salt[SALT_SIZ];
extern u_int8_t nmk_salt[SALT_SIZ];

/**
 * salted_secret
 * @len:	lenght of the salted secret
 * @value:	value of the salted secret
 */
struct salted_secret {
	u_int8_t	len;
	u_int8_t	value[72];
};

/**
 * sha256_ctx
 * @total:	total of the sha256 context
 * @state:	state of the context
 * @buffer:	buffer to calculate stuff
 */
struct sha256_ctx {
	u_int32_t	total[2];
	u_int32_t	state[8];
	u_int8_t	buffer[MAX_SECRET_SIZ];
};


/**
 * gen_passphrase - create a hash from a user input passphrase
 * @password:	user input password
 * @key:	resulting key
 * @salt:	salt type (NMK, DAK or NID)
 * @return
 *	0 on success, -1 on failure
 */
extern int gen_passphrase(const char *password, u_int8_t *key, const unsigned char *salt);

#endif /* __CRYPTO_H__ */

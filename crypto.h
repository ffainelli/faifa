/*
 *  crypto.h - crypto related stuff
 *
 * Copyright (C) 2007-2008 
 *	Xavier Carcelle <xavier.carcelle@gmail.com>
 *	Florian Fainelli <florian@openwrt.org>
 *	Nicolas Thill <nico@openwrt.org>
 *
 * License:
 *	GPLv2
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
extern int gen_passphrase(const unsigned char *password, unsigned char *key, const unsigned char *salt);

#endif /* __CRYPTO_H__ */

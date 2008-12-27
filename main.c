/*
 * main.c - program entry point and command line parsing 
 * 
 * Copyright (C) 2007-2008
 *	Xavier Carcelle <xavier.carcelle@gmail.com>
 *	Florian Fainelli <florian@openwrt.org>
 *	Nicolas Thill <nico@openwrt.org>
 *
 * Description:
 *	This file provides the program entry poin (main) as
 *	well as the arguments parsing and functionnal operations
 *  
 * License:
 *	GPLv2
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include "faifa.h"

#ifndef FAIFA_PROG
#define FAIFA_PROG "faifa"
#endif

/* Command line arguments storing */
int opt_help = 0;
int opt_interactive = 0;
int opt_key = 0;
extern int opt_verbose;
extern FILE *err_stream;
extern FILE *out_stream;
extern FILE *in_stream;

/**
 * error - display error message
 */
static void error(char *message)
{
	fprintf(stderr, "%s: %s\n", FAIFA_PROG, message);
}

/**
 * usage - show the program usage
 */
static void usage(void)
{
	fprintf(stderr, "-i : interface\n"
			"-m : show menu (no option required)\n"
			"-a : station MAC address\n"
			"-k : network key\n"
			"-v : be verbose (default: no)\n"
			"-e : error stream (default: stderr)\n"
			"-o : output stream (default: stdout)\n"
			"-s : input stream (default: stdin)\n"
			"-h : this help\n");
}

extern void menu(faifa_t *faifa);
extern void set_key(char *macaddr);

/**
 * main - main function of faifa
 * @argc:	number of arguments
 * @argv:	array of arguments
 */
int main(int argc, char **argv)
{
	faifa_t *faifa;
	char *opt_ifname;
	char *opt_macaddr;
	char *opt_err_stream = NULL;
	char *opt_out_stream = NULL;
	char *opt_in_stream = NULL;
	int c;

	fprintf(stdout, "Faifa for HomePlug AV (SVN revision %d)\n\n", SVN_REV);

	if (argc < 2) {
		usage();
		return -1;
	}

	while ((c = getopt(argc, argv, "i:ma:k:veosh")) != -1) {
		switch (c) {
			case 'i':
				opt_ifname = optarg;
				break;
			case 'm':
				opt_interactive = 1;
				break;
			case 'a':
				opt_macaddr = optarg;
				break;
			case 'k':
				opt_key = 1;
				break;
			case 'v':
				opt_verbose = 1;
				break;
			case 'e':
				opt_err_stream = optarg;
				break;
			case 'o':
				opt_out_stream = optarg;
				break;
			case 's':
				opt_in_stream = optarg;
				break;
			case 'h':
			default:
				opt_help = 1;
				break;
		}
	}

	if (opt_help) {
		usage();
		return -1;
	}

	if (opt_ifname == NULL)
		opt_ifname = "eth0";

	if (opt_err_stream == NULL)
		err_stream = stderr;
	else {
		err_stream = fopen(opt_err_stream, "w+");
		if (!err_stream) {
			perror("err_stream");
			return -1;
		}
	}
	
	if (opt_out_stream == NULL)
		out_stream = stdout;
	else {
		out_stream = fopen(opt_out_stream, "w+");
		if (!out_stream) {
			perror("out_stream");
			return -1;
		}
	}

	if (opt_in_stream == NULL)
		in_stream = stdin;
	else {
		in_stream = fopen(opt_in_stream, "rb");
		if (!in_stream) {
			perror("in_stream");
			return -1;
		}
	}
	
	faifa = faifa_init();
	if (faifa == NULL) {
		error("can't initialize Faifa library");
		return -1;
	}
	
	if (faifa_open(faifa, opt_ifname) == -1) {
		error(faifa_error(faifa));
		faifa_free(faifa);
		return -1;
	}

	if (opt_interactive)
		menu(faifa);

	faifa_close(faifa);
	faifa_free(faifa);
	
	return 0;
}

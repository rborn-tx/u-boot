// SPDX-License-Identifier: GPL-2.0+
/*
 * (C) Copyright 2009-2013 ADVANSEE
 * Benoît Thébaudeau <benoit.thebaudeau@advansee.com>
 *
 * Based on the mpc512x iim code:
 * Copyright 2008 Silicon Turnkey Express, Inc.
 * Martha Marx <mmarx@silicontkx.com>
 */

#include <common.h>
#include <command.h>
#include <console.h>
#include <fuse.h>
#include <mapmem.h>
#include <linux/errno.h>

static int strtou32(const char *str, unsigned int base, u32 *result)
{
	char *ep;

	*result = simple_strtoul(str, &ep, base);
	if (ep == str || *ep != '\0')
		return -EINVAL;

	return 0;
}

static int confirm_prog(void)
{
	puts("Warning: Programming fuses is an irreversible operation!\n"
			"         This may brick your system.\n"
			"         Use this command only if you are sure of "
					"what you are doing!\n"
			"\nReally perform this fuse programming? <y/N>\n");

	if (confirm_yesno())
		return 1;

	puts("Fuse programming aborted\n");
	return 0;
}

static int do_fuse(struct cmd_tbl *cmdtp, int flag, int argc,
		   char *const argv[])
{
	const char *op = cmd_arg1(argc, argv);
	int confirmed = 0, quiet = 0;
	u32 bank, word, cnt, val, cmp;
	ulong addr;
	void *buf, *start;
	int ret, i;

#define IF_NOT_QUIET(stmt) do { if (!quiet) { stmt; } } while(0)

	if (argc >= 2) {
		argc -= 2;
		argv += 2;
	}

	/* Handle common switches. */
	while (argc) {
		if (!strcmp(argv[0], "-y"))
			confirmed = 1;
		else if (!strcmp(argv[0], "-q"))
			quiet = 1;
		else
			break;
		argc--;
		argv++;
	}

	if (argc < 2 || strtou32(argv[0], 0, &bank) ||
			strtou32(argv[1], 0, &word))
		return CMD_RET_USAGE;

	if (!strcmp(op, "read")) {
		if (argc == 2)
			cnt = 1;
		else if (argc != 3 || strtou32(argv[2], 0, &cnt))
			return CMD_RET_USAGE;

		IF_NOT_QUIET(printf("Reading bank %u:\n", bank));
		for (i = 0; i < cnt; i++, word++) {
			if (!(i % 4))
				IF_NOT_QUIET(printf("\nWord 0x%.8x:", word));

			ret = fuse_read(bank, word, &val);
			if (ret)
				goto err;

			IF_NOT_QUIET(printf(" %.8x", val));
		}
		IF_NOT_QUIET(putc('\n'));
	} else if (!strcmp(op, "readm")) {
		if (argc == 3)
			cnt = 1;
		else if (argc != 4 || strtou32(argv[3], 0, &cnt))
			return CMD_RET_USAGE;

		addr = simple_strtoul(argv[2], NULL, 16);

		start = map_sysmem(addr, 4);
		buf = start;

		IF_NOT_QUIET(printf("Reading bank %u len %u to 0x%lx\n",
				    bank, cnt, addr));
		for (i = 0; i < cnt; i++, word++) {
			ret = fuse_read(bank, word, &val);
			if (ret)
				goto err;

			*((u32 *)buf) = val;
			buf += 4;
		}

		unmap_sysmem(start);
	} else if (!strcmp(op, "cmp")) {
		if (argc != 3 || strtou32(argv[2], 0, &cmp))
			return CMD_RET_USAGE;

		IF_NOT_QUIET(printf("Comparing bank %u:\n", bank));
		IF_NOT_QUIET(printf("\nWord 0x%.8x:", word));
		IF_NOT_QUIET(printf("\nValue 0x%.8x:", cmp));

		ret = fuse_read(bank, word, &val);
		if (ret)
			goto err;

		IF_NOT_QUIET(printf("0x%.8x\n", val));
		if (val != cmp) {
			IF_NOT_QUIET(printf("failed\n"));
			return CMD_RET_FAILURE;
		}
		IF_NOT_QUIET(printf("passed\n"));
	} else if (!strcmp(op, "sense")) {
		if (argc == 2)
			cnt = 1;
		else if (argc != 3 || strtou32(argv[2], 0, &cnt))
			return CMD_RET_USAGE;

		IF_NOT_QUIET(printf("Sensing bank %u:\n", bank));
		for (i = 0; i < cnt; i++, word++) {
			if (!(i % 4))
				IF_NOT_QUIET(printf("\nWord 0x%.8x:", word));

			ret = fuse_sense(bank, word, &val);
			if (ret)
				goto err;

			IF_NOT_QUIET(printf(" %.8x", val));
		}
		IF_NOT_QUIET(putc('\n'));
	} else if (!strcmp(op, "prog")) {
		if (argc < 3)
			return CMD_RET_USAGE;

		for (i = 2; i < argc; i++, word++) {
			if (strtou32(argv[i], 16, &val))
				return CMD_RET_USAGE;

			IF_NOT_QUIET(printf("Programming bank %u word "
					    "0x%.8x to 0x%.8x...\n",
					    bank, word, val));
			if (!confirmed && !confirm_prog())
				return CMD_RET_FAILURE;
			ret = fuse_prog(bank, word, val);
			if (ret)
				goto err;
		}
	} else if (!strcmp(op, "override")) {
		if (argc < 3)
			return CMD_RET_USAGE;

		for (i = 2; i < argc; i++, word++) {
			if (strtou32(argv[i], 16, &val))
				return CMD_RET_USAGE;

			IF_NOT_QUIET(printf("Overriding bank %u word "
					    "0x%.8x with 0x%.8x...\n",
					    bank, word, val));
			ret = fuse_override(bank, word, val);
			if (ret)
				goto err;
		}
	} else {
		return CMD_RET_USAGE;
	}

	return 0;

err:
	IF_NOT_QUIET(puts("ERROR\n"));
	return CMD_RET_FAILURE;

#undef IF_NOT_QUIET
}

U_BOOT_CMD(
	fuse, CONFIG_SYS_MAXARGS, 0, do_fuse,
	"Fuse sub-system",
	     "read [-q] <bank> <word> [<cnt>] - read 1 or 'cnt' fuse words,\n"
	"    starting at 'word'\n"
	"fuse cmp [-q] <bank> <word> <hexval> - compare 'hexval' to fuse\n"
	"    at 'word'\n"
	"fuse readm [-q] <bank> <word> <addr> [<cnt>] - read 1 or 'cnt' fuse words,\n"
	"    starting at 'word' into memory at 'addr'\n"
	"fuse sense [-q] <bank> <word> [<cnt>] - sense 1 or 'cnt' fuse words,\n"
	"    starting at 'word'\n"
	"fuse prog [-q] [-y] <bank> <word> <hexval> [<hexval>...] - program 1 or\n"
	"    several fuse words, starting at 'word' (PERMANENT)\n"
	"fuse override [-q] <bank> <word> <hexval> [<hexval>...] - override 1 or\n"
	"    several fuse words, starting at 'word'"
);

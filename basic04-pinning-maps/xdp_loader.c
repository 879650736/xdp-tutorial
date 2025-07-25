/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
	" - Allows selecting BPF program --progname name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

static const char *default_filename = "xdp_prog_kern.o";

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"reuse-maps",  no_argument,		NULL, 'M' },
	 "Reuse pinned maps"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progname",    required_argument,	NULL,  2  },
	 "Load program from function <name> in the ELF file", "<name>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";
const char *map_name    =  "xdp_stats_map";

/* Pinning maps under /sys/fs/bpf in subdir */
int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, struct config *cfg)
{
	char map_filename[PATH_MAX];
	int err, len;

	len = snprintf(map_filename, PATH_MAX, "%s/%s",
               cfg->pin_dir, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		return EXIT_FAIL_OPTION;
	}
	printf("map_filename: %s\n", map_filename);
	printf("map_name: %s\n", map_name);

	/* Existing/previous XDP prog might not have cleaned up */
	if (access(map_filename, F_OK ) != -1 ) {
		printf(" - Unpinning (remove) prev maps in %s/\n",
			       cfg->pin_dir);

		/* Basically calls unlink(3) on map_filename */
		err = bpf_object__unpin_maps(bpf_obj, cfg->pin_dir);
		if (err) {
			fprintf(stderr, "ERR: UNpinning maps in %s\n", cfg->pin_dir);
			return EXIT_FAIL_BPF;
		}
	}

	printf(" - Pinning maps in %s/\n", cfg->pin_dir);

	/* This will pin all maps in our bpf_object */
	err = bpf_object__pin_maps(bpf_obj, cfg->pin_dir);
	if (err) {
		fprintf(stderr, "ERR: Pinning maps in %s\n", cfg->pin_dir);
		return EXIT_FAIL_BPF;
	}

	return 0;
}


/* Reusing pinned maps under /sys/fs/bpf in subdir */
int reuse_pin_maps_in_bpf_object(struct bpf_object *bpf_obj, struct config *cfg)
{
	char map_filename[PATH_MAX];
	int len;

	len = snprintf(map_filename, PATH_MAX, "%s/%s",
               cfg->pin_dir, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		return EXIT_FAIL_OPTION;
	}
	printf("map_filename: %s\n", map_filename);
	printf("map_name: %s\n", map_name);

	/* Check if pinned map exists */
	if (access(map_filename, F_OK ) != -1 ) {
		if (verbose)
			printf(" - Reusing pinned maps from %s/\n", cfg->pin_dir);
		
		int pinned_map_fd = bpf_obj_get(map_filename);
		if (pinned_map_fd < 0) {
			fprintf(stderr, "ERR: Failed to get pinned map from %s\n", map_filename);
			return EXIT_FAIL_BPF;
		}
		
		struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, map_name);
		if (!map) {
			fprintf(stderr, "ERR: Failed to find map %s in BPF object\n", map_name);
			return EXIT_FAIL_BPF;
		}
		
		int err = bpf_map__reuse_fd(map, pinned_map_fd);
		if (err) {
			fprintf(stderr, "ERR: Failed to reuse map fd\n");
			return EXIT_FAIL_BPF;
		}
	} else {
		if (verbose)
			printf(" - No existing pinned maps found, will pin new maps in %s/\n", cfg->pin_dir);
		
		/* Clean up any existing maps first */
        int err = bpf_object__unpin_maps(bpf_obj, cfg->pin_dir);
        if (err && verbose) {
            printf(" - No previous maps to unpin (this is normal)\n");
        }

		/* Pin the maps since they don't exist yet */
		err = bpf_object__pin_maps(bpf_obj, cfg->pin_dir);
		if (err) {
			fprintf(stderr, "ERR: Pinning maps in %s\n", cfg->pin_dir);
			return EXIT_FAIL_BPF;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct xdp_program *program;
	int err, len;

	struct config cfg = {
		.attach_mode = XDP_MODE_NATIVE,
		.ifindex     = -1,
		.do_unload   = false,
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	/* Cmdline options can change progname */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	if (cfg.do_unload) {
		if (!cfg.reuse_maps) {
		/* TODO: Miss unpin of maps on unload */
		}
		/* return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0); */
	}

	/* Initialize the pin_dir configuration */
	len = snprintf(cfg.pin_dir, 512, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}


	program = load_bpf_and_xdp_attach(&cfg);
	if (!program)
		return EXIT_FAIL_BPF;

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used program(%s)\n",
		       cfg.filename, cfg.progname);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}

	/* Use the --dev name as subdir for exporting/pinning maps */
	if (!cfg.reuse_maps) {
		err = pin_maps_in_bpf_object(xdp_program__bpf_obj(program), &cfg);
		if (err) {
			fprintf(stderr, "ERR: pinning maps\n");
			return err;
		}
	}else {
		err = reuse_pin_maps_in_bpf_object(xdp_program__bpf_obj(program), &cfg);
		if (err) {
			fprintf(stderr, "ERR: pinning maps\n");
			return err;
		}
	}

	return EXIT_OK;
}

/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Gamepad Quirk Support
 *
 *  CLI tool for managing gamepad quirk profiles.
 *  Validates JSON profiles, manages HMAC keys, installs/removes
 *  signed profiles to the system directory.
 *
 *  Usage:
 *    bluez-quirkctl install <file.json>   -- validate, sign, install
 *    bluez-quirkctl remove <name>         -- uninstall a profile
 *    bluez-quirkctl list                  -- list installed profiles
 *    bluez-quirkctl validate <file.json>  -- check without installing
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>

#include <json-c/json.h>

#define QUIRK_DIR "/var/lib/bluez/quirks"
#define USER_QUIRK_DIR "/.config/bluez/quirks"
#define HMAC_KEY_PATH QUIRK_DIR "/.hmac_key"
#define HMAC_KEY_SIZE 32
#define MAX_DESCRIPTOR_SIZE 2048
#define JSON_EXT ".json"
#define SIG_EXT ".sig"

static const char *prog;

static void usage(void)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s install <file.json>    Install a quirk profile\n"
		"  %s remove <name>          Remove an installed profile\n"
		"  %s list                   List installed profiles\n"
		"  %s validate <file.json>   Validate without installing\n",
		prog, prog, prog, prog);
}

/*
 * Ensure the quirk directory exists with correct permissions.
 */
static int ensure_dir(void)
{
	struct stat st;

	if (stat(QUIRK_DIR, &st) < 0) {
		if (errno == ENOENT) {
			if (mkdir(QUIRK_DIR, 0755) < 0) {
				fprintf(stderr, "Cannot create %s: %s\n",
					QUIRK_DIR, strerror(errno));
				return -1;
			}
			if (chmod(QUIRK_DIR, 0755) < 0) {
				fprintf(stderr, "Cannot chmod %s: %s\n",
					QUIRK_DIR, strerror(errno));
				return -1;
			}
		} else {
			fprintf(stderr, "Cannot stat %s: %s\n",
				QUIRK_DIR, strerror(errno));
			return -1;
		}
	}

	return 0;
}

/*
 * Generate HMAC key if it doesn't exist.
 */
static int ensure_hmac_key(void)
{
	int fd;
	uint8_t key[HMAC_KEY_SIZE];
	ssize_t n;
	const char *urandom = "/dev/urandom";

	if (access(HMAC_KEY_PATH, F_OK) == 0)
		return 0;

	fd = open(urandom, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n",
			urandom, strerror(errno));
		return -1;
	}

	n = read(fd, key, HMAC_KEY_SIZE);
	close(fd);

	if (n != HMAC_KEY_SIZE) {
		fprintf(stderr, "Failed to read random bytes\n");
		return -1;
	}

	fd = open(HMAC_KEY_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		fprintf(stderr, "Cannot create %s: %s\n",
			HMAC_KEY_PATH, strerror(errno));
		return -1;
	}

	/* Write key as hex string */
	char hex[HMAC_KEY_SIZE * 2 + 2];
	int i;
	for (i = 0; i < HMAC_KEY_SIZE; i++)
		snprintf(hex + i * 2, 3, "%02x", key[i]);
	hex[HMAC_KEY_SIZE * 2] = '\n';
	hex[HMAC_KEY_SIZE * 2 + 1] = '\0';

	if (write(fd, hex, HMAC_KEY_SIZE * 2 + 1) < 0) {
		fprintf(stderr, "Cannot write key: %s\n", strerror(errno));
		close(fd);
		unlink(HMAC_KEY_PATH);
		return -1;
	}

	close(fd);
	printf("Generated HMAC key: %s\n", HMAC_KEY_PATH);
	return 0;
}

/*
 * Compute HMAC-SHA256 via openssl CLI.
 */
static char *compute_hmac(const char *file_path)
{
	char cmd[1024];
	char line[256];
	char *result = NULL;
	FILE *p;
	char *eq;

	snprintf(cmd, sizeof(cmd),
		"openssl dgst -sha256 -hmac \"$(cat " HMAC_KEY_PATH ")\" "
		"-hex < '%s' 2>/dev/null", file_path);

	p = popen(cmd, "r");
	if (!p)
		return NULL;

	while (fgets(line, sizeof(line), p)) {
		eq = strstr(line, "= ");
		if (eq) {
			eq += 2;
			/* trim */
			char *end = eq + strlen(eq) - 1;
			while (end > eq && (*end == '\n' || *end == '\r'
						|| *end == ' '))
				*end-- = '\0';
			result = strdup(eq);
			break;
		}
	}

	pclose(p);
	return result;
}

/*
 * Validate JSON profile structure.
 */
static int validate_profile(const char *path, char **out_name)
{
	json_object *root, *jname, *jmatch, *jdesc;
	FILE *f;
	const char *name, *desc_hex;
	size_t desc_len;
	uint8_t *desc_buf;
	int parsed;

	f = fopen(path, "re");
	if (!f) {
		fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
		return -1;
	}

	root = json_object_from_fd(fileno(f));
	fclose(f);

	if (!root) {
		fprintf(stderr, "Invalid JSON: %s\n", path);
		return -1;
	}

	/* name */
	if (!json_object_object_get_ex(root, "name", &jname) ||
	    json_object_get_type(jname) != json_type_string) {
		fprintf(stderr, "Missing or invalid 'name'\n");
		goto fail;
	}
	name = json_object_get_string(jname);

	/* match */
	if (!json_object_object_get_ex(root, "match", &jmatch) ||
	    json_object_get_type(jmatch) != json_type_object) {
		fprintf(stderr, "Missing or invalid 'match'\n");
		goto fail;
	}

	/* match must have vendor_id+product_id or device_name */
	{
		json_object *jtmp;
		bool has_vidpid = false, has_name = false;

		if (json_object_object_get_ex(jmatch, "vendor_id", &jtmp)) {
			json_object *jpid;
			if (json_object_object_get_ex(jmatch, "product_id",
							&jpid))
				has_vidpid = true;
		}

		if (json_object_object_get_ex(jmatch, "device_name", &jtmp))
			has_name = true;

		if (!has_vidpid && !has_name) {
			fprintf(stderr,
				"match needs vendor_id+product_id "
				"or device_name\n");
			goto fail;
		}
	}

	/* hid_descriptor */
	if (!json_object_object_get_ex(root, "hid_descriptor", &jdesc) ||
	    json_object_get_type(jdesc) != json_type_string) {
		fprintf(stderr, "Missing or invalid 'hid_descriptor'\n");
		goto fail;
	}

	desc_hex = json_object_get_string(jdesc);
	desc_len = strlen(desc_hex);

	/* Quick size estimate: each byte = 2 hex chars + optional space */
	if (desc_len > MAX_DESCRIPTOR_SIZE * 5) {
		fprintf(stderr, "Descriptor too large (max %d bytes)\n",
			MAX_DESCRIPTOR_SIZE);
		goto fail;
	}

	/* Try to parse the descriptor hex */
	desc_buf = malloc(MAX_DESCRIPTOR_SIZE);
	if (!desc_buf) {
		fprintf(stderr, "Out of memory\n");
		goto fail;
	}

	{
		const char *p = desc_hex;
		unsigned int byte;
		char buf[3];
		int len = 0;

		while (*p && len < MAX_DESCRIPTOR_SIZE) {
			while (*p == ' ' || *p == '\t' || *p == '\n'
				|| *p == '\r')
				p++;
			if (!*p)
				break;
			if (!p[0] || !p[1]) {
				fprintf(stderr, "Odd-length hex string\n");
				free(desc_buf);
				goto fail;
			}

			buf[0] = p[0];
			buf[1] = p[1];
			buf[2] = '\0';
			if (sscanf(buf, "%2x", &byte) != 1) {
				fprintf(stderr, "Invalid hex: '%s'\n", buf);
				free(desc_buf);
				goto fail;
			}
			p += 2;
			len++;
		}

		parsed = len;
	}

	free(desc_buf);

	if (parsed <= 0 || parsed > MAX_DESCRIPTOR_SIZE) {
		fprintf(stderr, "Invalid descriptor size: %d bytes\n", parsed);
		goto fail;
	}

	printf("Valid: '%s' (%d byte descriptor)\n", name, parsed);

	if (out_name)
		*out_name = strdup(name);

	json_object_put(root);
	return 0;

fail:
	json_object_put(root);
	return -1;
}

/*
 * Derive profile name from filename (strip path and .json extension).
 */
static const char *profile_name_from_path(const char *path)
{
	const char *base;
	const char *dot;

	base = strrchr(path, '/');
	base = base ? base + 1 : path;

	dot = strrchr(base, '.');
	if (dot && strcmp(dot, JSON_EXT) == 0)
		return base; /* Returns up to . but we need the name */

	/* Return the base name without extension */
	static char name_buf[256];
	size_t len;

	if (dot)
		len = dot - base;
	else
		len = strlen(base);

	if (len >= sizeof(name_buf))
		len = sizeof(name_buf) - 1;

	memcpy(name_buf, base, len);
	name_buf[len] = '\0';
	return name_buf;
}

static int cmd_install(const char *path)
{
	char dest[512], sig_dest[512];
	char *name = NULL;
	char *sig;
	int ret;
	struct stat st;

	if (getuid() != 0) {
		fprintf(stderr, "Error: install requires root\n"
			"Use: sudo %s install %s\n", prog, path);
		return 1;
	}

	if (validate_profile(path, &name) < 0)
		return 1;

	if (ensure_dir() < 0)
		return 1;

	if (ensure_hmac_key() < 0)
		return 1;

	/* Check for existing profile with same name */
	snprintf(dest, sizeof(dest), "%s/%s" JSON_EXT, QUIRK_DIR, name);
	if (stat(dest, &st) == 0) {
		fprintf(stderr, "Profile '%s' already exists. "
			"Remove it first.\n", name);
		free(name);
		return 1;
	}

	/* Copy profile to system dir */
	ret = snprintf(dest, sizeof(dest), "%s/%s" JSON_EXT,
			QUIRK_DIR, name);
	if (ret < 0 || ret >= (int)sizeof(dest)) {
		fprintf(stderr, "Path too long\n");
		free(name);
		return 1;
	}

	{
		char cmd[1024];
		snprintf(cmd, sizeof(cmd), "cp '%s' '%s'", path, dest);
		if (system(cmd) != 0) {
			fprintf(stderr, "Failed to copy profile\n");
			free(name);
			return 1;
		}
	}

	if (chmod(dest, 0644) < 0) {
		fprintf(stderr, "chmod failed: %s\n", strerror(errno));
		free(name);
		return 1;
	}

	/* Generate signature */
	sig = compute_hmac(dest);
	if (!sig) {
		fprintf(stderr, "Failed to compute signature\n");
		free(name);
		return 1;
	}

	snprintf(sig_dest, sizeof(sig_dest), "%s/%s" JSON_EXT SIG_EXT,
		QUIRK_DIR, name);

	{
		FILE *sf = fopen(sig_dest, "we");
		if (!sf) {
			fprintf(stderr, "Cannot create %s: %s\n",
				sig_dest, strerror(errno));
			free(sig);
			free(name);
			return 1;
		}
		fprintf(sf, "%s\n", sig);
		fclose(sf);
	}

	chmod(sig_dest, 0644);

	printf("Installed: %s\n", dest);
	printf("Signature: %s\n", sig_dest);

	free(sig);
	free(name);
	return 0;
}

static int cmd_remove(const char *name)
{
	char json_path[512], sig_path[512];

	if (getuid() != 0) {
		fprintf(stderr, "Error: remove requires root\n"
			"Use: sudo %s remove %s\n", prog, name);
		return 1;
	}

	snprintf(json_path, sizeof(json_path), "%s/%s" JSON_EXT,
		QUIRK_DIR, name);
	snprintf(sig_path, sizeof(sig_path), "%s/%s" JSON_EXT SIG_EXT,
		QUIRK_DIR, name);

	if (unlink(json_path) < 0) {
		fprintf(stderr, "Cannot remove %s: %s\n",
			json_path, strerror(errno));
		return 1;
	}

	unlink(sig_path); /* may not exist */

	printf("Removed: %s\n", json_path);
	return 0;
}

static int cmd_list(void)
{
	DIR *d;
	struct dirent *ent;
	size_t nlen;
	int count = 0;

	d = opendir(QUIRK_DIR);
	if (!d) {
		fprintf(stderr, "Cannot open %s: %s\n",
			QUIRK_DIR, strerror(errno));
		return 1;
	}

	printf("Installed quirk profiles in %s:\n", QUIRK_DIR);

	while ((ent = readdir(d)) != NULL) {
		nlen = strlen(ent->d_name);
		if (nlen <= strlen(JSON_EXT))
			continue;
		if (strcmp(ent->d_name + nlen - strlen(JSON_EXT), JSON_EXT)
								!= 0)
			continue;

		/* Skip .hmac_key and other dotfiles */
		if (ent->d_name[0] == '.')
			continue;

		printf("  %.*s\n", (int)(nlen - strlen(JSON_EXT)),
			ent->d_name);
		count++;
	}

	closedir(d);

	if (count == 0)
		printf("  (none)\n");

	return 0;
}

int main(int argc, char *argv[])
{
	prog = argv[0];

	if (argc < 2) {
		usage();
		return 1;
	}

	if (strcmp(argv[1], "install") == 0) {
		if (argc < 3) {
			fprintf(stderr, "Usage: %s install <file.json>\n", prog);
			return 1;
		}
		return cmd_install(argv[2]);
	}

	if (strcmp(argv[1], "remove") == 0) {
		if (argc < 3) {
			fprintf(stderr, "Usage: %s remove <name>\n", prog);
			return 1;
		}
		return cmd_remove(argv[2]);
	}

	if (strcmp(argv[1], "list") == 0) {
		return cmd_list();
	}

	if (strcmp(argv[1], "validate") == 0) {
		if (argc < 3) {
			fprintf(stderr, "Usage: %s validate <file.json>\n",
				prog);
			return 1;
		}
		return validate_profile(argv[2], NULL);
	}

	fprintf(stderr, "Unknown command: %s\n", argv[1]);
	usage();
	return 1;
}

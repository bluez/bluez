/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

struct obex_plugin_desc {
	const char *name;
	int (*init) (void);
	void (*exit) (void);
};

#ifdef OBEX_PLUGIN_BUILTIN
#define OBEX_PLUGIN_DEFINE(name, init, exit) \
		const struct obex_plugin_desc __obex_builtin_ ## name = { \
			#name, init, exit \
		};
#else
#if EXTERNAL_PLUGINS
#define OBEX_PLUGIN_DEFINE(name,init,exit) \
		extern struct obex_plugin_desc obex_plugin_desc \
				__attribute__ ((visibility("default"))); \
		const struct obex_plugin_desc obex_plugin_desc = { \
			#name, init, exit \
		};
#else
#error "Requested non built-in plugin, while external plugins is disabled"
#endif
#endif

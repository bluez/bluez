#ifndef __GMODULE_H
#define __GMODULE_H

#include <gmain.h>

typedef struct _GModule GModule;

typedef enum {
	G_MODULE_BIND_LAZY	= 1 << 0,
	G_MODULE_BIND_LOCAL	= 1 << 1,
	G_MODULE_BIND_MASK	= 0x03
} GModuleFlags;

GModule *g_module_open(const gchar *file_name, GModuleFlags flags);
gboolean g_module_symbol(GModule *module, const gchar *symbol_name,
				gpointer *symbol);
const gchar *g_module_name(GModule *module);
gboolean g_module_close(GModule *module);
const gchar *g_module_error(void);

#endif /* __GMODULE_H */

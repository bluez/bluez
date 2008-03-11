#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>

#include <gmain.h>
#include <gmodule.h>

struct _GModule {
	void *handle;
	gchar *file_name;
};

static const char *dl_error_string = NULL;

GModule *g_module_open(const gchar *file_name, GModuleFlags flags)
{
	GModule *module;

	module = g_try_new0(GModule, 1);
	if (module == NULL) {
		dl_error_string = strerror(ENOMEM);
		return NULL;
	}

	module->handle = dlopen(file_name, flags);

	if (module->handle == NULL) {
		dl_error_string = dlerror();
		g_free(module);
		return NULL;
	}

	module->file_name = g_strdup(file_name);

	return module;
}

gboolean g_module_symbol(GModule *module, const gchar *symbol_name,
				gpointer *symbol)
{
	void *sym;

	dlerror();
	sym = dlsym(module->handle, symbol_name);
	dl_error_string = dlerror();

	if (dl_error_string != NULL)
		return FALSE;

	*symbol = sym;

	return TRUE;
}

gboolean g_module_close(GModule *module)
{
	if (dlclose(module->handle) != 0) {
		dl_error_string = dlerror();
		return FALSE;
	}

	g_free(module->file_name);
	g_free(module);

	return TRUE;
}

const gchar *g_module_error(void)
{
	const char *str;

	str = dl_error_string;
	dl_error_string = NULL;

	return str;
}

const gchar *g_module_name(GModule *module)
{
	if (module == NULL)
		return NULL;

	return module->file_name;
}

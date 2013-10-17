/*
 * Copyright (C) 2006 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __CUTILS_PROPERTIES_H
#define __CUTILS_PROPERTIES_H

#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PROPERTY_KEY_MAX   32
#define PROPERTY_VALUE_MAX  92

/* property_get: returns the length of the value which will never be
** greater than PROPERTY_VALUE_MAX - 1 and will always be zero terminated.
** (the length does not include the terminating zero).
**
** If the property read fails or returns an empty value, the default
** value is used (if nonnull).
*/
static inline int property_get(const char *key, char *value,
						const char *default_value)
{
	const char *env;

	env = getenv(key);
	if (!env)
		env = default_value;

	if (!value)
		return 0;

	strncpy(value, env, PROPERTY_VALUE_MAX);

	return strlen(value);
}

/* property_set: returns 0 on success, < 0 on failure
*/
static inline int property_set(const char *key, const char *value)
{
	return setenv(key, value, 0);
}

#ifdef __cplusplus
}
#endif

#endif

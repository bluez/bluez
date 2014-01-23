/*
 * Copyright (C) 2014 Intel Corporation
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
 *
 */

#include "if-main.h"
#include "../hal-utils.h"

const btrc_interface_t *if_rc = NULL;

static btrc_callbacks_t rc_cbacks = {
	.size = sizeof(rc_cbacks),
};

/* init */

static void init_p(int argc, const char **argv)
{
	RETURN_IF_NULL(if_rc);

	EXEC(if_rc->init, &rc_cbacks);
}

/* cleanup */

static void cleanup_p(int argc, const char **argv)
{
	RETURN_IF_NULL(if_rc);

	EXECV(if_rc->cleanup);
	if_rc = NULL;
}

static struct method methods[] = {
	STD_METHOD(init),
	STD_METHOD(cleanup),
	END_METHOD
};

const struct interface rc_if = {
	.name = "rc",
	.methods = methods
};

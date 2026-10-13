/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <sys/socket.h>

int __wrap_socket(int domain, int type, int protocol);
int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t length);
int __wrap_setsockopt(int fd, int level, int opt, const void *value,
							socklen_t length);
int __wrap_getsockopt(int fd, int level, int opt, void *value,
							socklen_t *length);
int __real_setsockopt(int fd, int level, int opt, const void *value,
							socklen_t length);

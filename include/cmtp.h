/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2002-2004  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation;
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
 *  CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
 *  COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
 *  SOFTWARE IS DISCLAIMED.
 *
 *
 *  $Id$
 */

#ifndef __CMTP_H
#define __CMTP_H

#ifdef __cplusplus
extern "C" {
#endif

/* CMTP defaults */
#define CMTP_MINIMUM_MTU 152
#define CMTP_DEFAULT_MTU 672

/* CMTP ioctl defines */
#define CMTPCONNADD	_IOW('C', 200, int)
#define CMTPCONNDEL	_IOW('C', 201, int)
#define CMTPGETCONNLIST	_IOR('C', 210, int)
#define CMTPGETCONNINFO	_IOR('C', 211, int)

#define CMTP_LOOPBACK	0

struct cmtp_connadd_req {
	int sock;	/* Connected socket */
	uint32_t flags;
};

struct cmtp_conndel_req {
	bdaddr_t bdaddr;
	uint32_t flags;
};

struct cmtp_conninfo {
	bdaddr_t bdaddr;
	uint32_t flags;
	uint16_t state;
	int      num;
};

struct cmtp_connlist_req {
	uint32_t cnum;
	struct cmtp_conninfo *ci;
};

#ifdef __cplusplus
}
#endif

#endif /* __CMTP_H */

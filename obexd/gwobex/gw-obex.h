/**
  @file gw-obex.h

  OSSO GW OBEX Connectivity Library and API

  @author Johan Hedberg <johan.hedberg@nokia.com>

  Copyright (C) 2004-2005 Nokia Corporation. All rights reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License, version 2.1, as published by the Free Software Foundation.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the
  Free Software Foundation, Inc., 59 Temple Place - Suite 330,
  Boston, MA 02111-1307, USA.

*/
#ifndef _GW_OBEX_H_
#define _GW_OBEX_H_

#include <glib.h>
#include <openobex/obex.h>

/**
 * @name GW OBEX Error Codes
 * The error codes returned by many of the functions refer either to an OBEX
 * Protocol error or to a GW OBEX error. If the error code is less that 256, it
 * refers to an OBEX error, othervice it refers to a GW_OBEX_ERROR_* error.
 * @{
*/

/** Transport connection was disconnected */
#define GW_OBEX_ERROR_DISCONNECT        256

/** Operation was aborted */
#define GW_OBEX_ERROR_ABORT             257

/** GW OBEX internal error */
#define GW_OBEX_ERROR_INTERNAL          258

/** Unable to connecto to the specified service (UUID) */
#define GW_OBEX_ERROR_NO_SERVICE        259

/** Unable to create connection */
#define GW_OBEX_ERROR_CONNECT_FAILED    260

/** Timeout while waiting for data from the remote device */
#define GW_OBEX_ERROR_TIMEOUT           261

/** Remote device returned invalid/corrupted data */
#define GW_OBEX_ERROR_INVALID_DATA      262

/** Invalid parameters given to gwobex */
#define GW_OBEX_ERROR_INVALID_PARAMS    263

/** Local access error (e.g. read/write/open failed for local file) */
#define GW_OBEX_ERROR_LOCAL_ACCESS      264

/** Another operation is in progress */
#define GW_OBEX_ERROR_BUSY              265

/** No data currently available */
#define GW_OBEX_ERROR_NO_DATA           266


/** @} */

/** Value used if target length for put or get is not known */
#define GW_OBEX_UNKNOWN_LENGTH -1

/** Standard folder browsing service UUID (give this as a parameter to
 *  gw_obex_setup_* to connect to folder browsing service */
#define OBEX_FTP_UUID \
    "\xF9\xEC\x7B\xC4\x95\x3C\x11\xD2\x98\x4E\x52\x54\x00\xDC\x9E\x09"
/** Length of OBEX_FTP_UUID */
#define OBEX_FTP_UUID_LEN 16

/** Phone Book Access Profile UUID */
#define OBEX_PBAP_UUID \
    "\x79\x61\x35\xF0\xF0\xC5\x11\xD8\x09\x66\x08\x00\x20\x0C\x9A\x66"
/** Length of OBEX_PBAP_UUID */
#define OBEX_PBAP_UUID_LEN 16

/** IrMC Sync Profile UUID */
#define OBEX_SYNC_UUID \
	"IRMC-SYNC"
/** Length of OBEX_SYNC_UUID */
#define OBEX_SYNC_UUID_LEN 9

/** Struct containing the context of a gwobex connection */
typedef struct gw_obex GwObex;

/** Objecct transfer handle */
typedef struct gw_obex_xfer GwObexXfer;

/** Callback type for ongoing transfers
 * @param ctx  GwObexXfer pointer for the transfer
 * @param data Optional pointer to user data
 */
typedef void (*gw_obex_xfer_cb_t) (GwObexXfer *xfer,
                                   gpointer data);

/** Callback type for transport connection loss
 * @param ctx  GwObex pointer for the connection
 * @param data Optional pointer to user data
 */
typedef void (*gw_obex_disconnect_cb_t) (GwObex *ctx,
                                         gpointer data);

/** Callback type for progress information
 * Only used for the synchronous transfer functions.
 * @param ctx       GwObex pointer for the connection
 * @param obex_cmd  eg. OBEX_CMD_PUT
 * @param current   Bytes transfered
 * @param target    Total length (or GW_OBEX_UNKNOWN_LENGTH)
 * @param data      Optional pointer to user data
 */
typedef void (*gw_obex_progress_cb_t) (GwObex *ctx, gint obex_cmd,
                                       gint current, gint target,
                                       gpointer data);

/** Callback type for checking if the operation should be canceled.
 * Only used for the synchronous functions.
 * In the GNOME VFS case the callback function should be
 * gnome_vfs_cancellation_check().
 * @param data Optional pointer to user data
 * @returns TRUE if the operation should be canceled, FALSE othervice
 */
typedef gboolean (*gw_obex_cancel_cb_t) (gpointer data);


/**
 * @name Functions for connecting and disconnecting
 * With these functions you can create and and disconnect connections. You can
 * either connect using a filename (e.g. "/dev/rfcomm0") or using a file
 * descriptor (e.g. a RFCOMM socket).
 * @{
 */

/** Open connection using a local device node and setup parameters.
 * This function should be called before calling any other functions. The
 * pointer returned by this function should be passed to the other functions.
 *
 * @param device   The local device which should be opened for the connection
 * @param uuid     UUID of service to connect to. NULL for the default service
 *                 (INBOX).
 * @param uuid_len Length (in bytes) of UUID
 * @param context  GMainContext to attach to (or NULL for the default one)
 * @param error    Place to store error code on failure (NULL if not interested)
 *
 * @returns A pointer, NULL on failure
 *  This pointer should be passed to the other obex_* functions.
 **/
GwObex *gw_obex_setup_dev(const gchar *device,
                          const gchar *uuid,
                          gint uuid_len,
                          GMainContext *context,
                          gint *error);


/** Setup OBEX connection using an opened file descriptor
 * This function should be called before calling any other functions. The
 * pointer returned by this function should be passed to the other functions.
 *
 * @param fd       Opened file descriptor to use for the connection
 * @param uuid     UUID of service to connect to. NULL for the default service
 *                 (INBOX).
 * @param uuid_len Length (in bytes) of UUID
 * @param context  GMainContext to attach to (or NULL for the default one)
 * @param error    Place to store error code on failure (NULL if not interested)
 *
 * @returns A pointer, NULL on failure
 *  This pointer should be passed to the other obex_* functions.
 **/
GwObex *gw_obex_setup_fd(int fd,
                         const gchar *uuid,
                         gint uuid_len,
                         GMainContext *context,
                         gint *error);


/** Close GW OBEX connection and free all memory associated with it.
 *
 * @param ctx Pointer returned by gw_obex_setup().
 *  Cannot be used anymore after this calling this function.
 */
void gw_obex_close(GwObex *ctx);

/** @} */

/**
 * @name Registering callback functions
 * With these functions you can register your own callback functions
 * to gwobex to receive indications about special events.
 * @{
 */

/** Set function to be called when a disconnection happens.
 *  You may (and probably should) call gw_obex_close() if this function is
 *  called.
 * @param ctx      Pointer returned by gw_obex_setup()
 * @param callback Function to call
 * @param data     Optional data to pass to the callback function
 */
void gw_obex_set_disconnect_callback(GwObex *ctx,
                                     gw_obex_disconnect_cb_t callback,
                                     gpointer data);


/** Set function to be called when progress for a put or get operation happens.
 * Only used for the synchronous transfer functions.
 *
 * @param ctx      Pointer returned by gw_obex_setup()
 * @param callback Function to call
 * @param data     Optional data to pass to the callback function
 */
void gw_obex_set_progress_callback(GwObex *ctx,
                                   gw_obex_progress_cb_t callback,
                                   gpointer data);


/** Set function to be called to check if the current operation should be
 * canceled. In the GNOME VFS case the callback function should be
 * gnome_vfs_cancellation_check(). The callback function should return TRUE if
 * the operation should be canceled and FALSE othervice.
 *
 * Only used for the synchronous transfer functions.
 * 
 * @param ctx      Pointer returned by gw_obex_setup()
 * @param callback Function to call
 * @param data     Pointer to pass to the callback function
 */
void gw_obex_set_cancel_callback(GwObex *ctx,
                                 gw_obex_cancel_cb_t callback,
                                 gpointer data);

/** @} */

/**
 * @name Functions for performing synchronous remote operations
 * Once you have setup a connection using one of the gw_obex_setup_* functions,
 * you can perform different remote transactions using these functions.
 * @{
 */

/** Get the capability object from the connected remote device.
 *
 * @param ctx     Pointer returned by gw_obex_setup()
 * @param cap     Place to store the fetched object.
 *                 g_free() when not needed anymore.
 * @param cap_len Place to store the size of the fetched object
 * @param error   Place to store a possible error code
 *   (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_get_capability(GwObex *ctx,
                                gchar **cap,
                                gint *cap_len,
                                gint *error);


/** Get a file from the remote device.
 *
 * @param ctx    Pointer returned by gw_obex_setup()
 * @param local  Local filename (null terminated UTF-8)
 * @param remote Remote filename (null terminated UTF-8)
 * @param type   MIME-type of the object
 * @param error  Place to store error code on failure
 *               (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_get_file(GwObex *ctx,
                          const gchar *local,
                          const gchar *remote,
                          const gchar *type,
                          gint *error);


/** Send a file to the remote device.
 *
 * @param ctx    Pointer returned by gw_obex_setup()
 * @param local  Local filename (null terminated UTF-8)
 * @param remote Remote filename (null terminated UTF-8)
 * @param type   MIME-type of the object
 * @param error  Place to store error code on failure
 *               (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_put_file(GwObex *ctx,
                          const gchar *local,
                          const gchar *remote,
                          const gchar *type,
                          gint *error);


/** Get a file from the remote device and write it to a file descriptor
 *
 * @param ctx    Pointer returned by gw_obex_setup()
 * @param fd     File descriptor to write the file into
 * @param remote Remote filename (null terminated UTF-8)
 * @param type   MIME-type of the object
 * @param error  Place to store error code on failure
 *               (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_get_fd(GwObex *ctx, gint fd,
                        const gchar *remote,
                        const gchar *type,
                        gint *error);

/** Read data from a file descriptor and send it to the remote device
 *
 * @param ctx    Pointer returned by gw_obex_setup()
 * @param fd     File descriptor to read the data from
 * @param remote Remote filename (null terminated UTF-8)
 * @param type   MIME-type of the object
 * @param error  Place to store error code on failure
 *               (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_put_fd(GwObex *ctx, gint fd,
                        const gchar *remote,
                        const gchar *type,
                        gint *error);

/** Get an object from the remote device and store it in a memory buffer.
 * Either remote filename or type must be supplied (or both).
 *
 * @param ctx      Pointer returned by gw_obex_setup()
 * @param remote   Remote filename (null terminated UTF-8)
 * @param type     MIME-type of the object
 * @param buf      Buffer to store the object in.
 *                  g_free() when not needed anymore.
 * @param buf_size Place to store length of fetched object
 * @param error    Place to store error code on failure
 *                 (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_get_buf(GwObex *ctx, const gchar *remote, const gchar *type,
                         gchar **buf, gint *buf_size, gint *error);


/** Send a object located in a memory buffer to the remote device.
 * Either remote filename or type must be supplied (or both)
 *
 * @param ctx      Pointer returned by gw_obex_setup()
 * @param remote   Remote filename (null terminated UTF-8)
 * @param type     MIME-type of the object
 * @param buf      Buffer containing the object
 * @param buf_size Buffer (object) size
 * @param time     Last modification time of object (or -1 if not known)
 * @param error    Place to store error code on failure
 *                 (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_put_buf(GwObex *ctx, const gchar *remote, const gchar *type,
                         const gchar *buf, gint buf_size, gint time, gint *error);


/** Get an object from the remote device and store it in a memory buffer.
 * Either remote filename or type must be supplied (or both).
 *
 * @param ctx          Pointer returned by gw_obex_setup()
 * @param remote       Remote filename (null terminated UTF-8)
 * @param type         MIME-type of the object
 * @param apparam      Application parameters of the object
 * @param apparam_size Application parameters size
 * @param buf          Buffer to store the object in.
 *                      g_free() when not needed anymore.
 * @param buf_size     Place to store length of fetched object
 * @param error        Place to store error code on failure
 *                     (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_get_buf_with_apparam(GwObex *ctx, const gchar *remote, const gchar *type,
                                      const guint8 *apparam, gint apparam_size,
                                      gchar **buf, gint *buf_size, gint *error);


/** Send a object located in a memory buffer to the remote device.
 * Either remote filename or type must be supplied (or both)
 *
 * @param ctx          Pointer returned by gw_obex_setup()
 * @param remote       Remote filename (null terminated UTF-8)
 * @param type         MIME-type of the object
 * @param apparam      Application parameters of the object
 * @param apparam_size Application parameters size
 * @param buf          Buffer containing the object
 * @param buf_size     Buffer (object) size
 * @param time         Last modification time of object (or -1 if not known)
 * @param error        Place to store error code on failure
 *                     (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_put_buf_with_apparam(GwObex *ctx, const gchar *remote, const gchar *type,
                                     const guint8 *apparam, gint apparam_size,
                                     const gchar *buf, gint buf_size, gint time, gint *error);


/** Change directory (relative to the current one).
 *
 * @param ctx   Pointer returned by gw_obex_setup()
 * @param dir   New directory to change to (null terminated UTF-8),
 *              ".." to go up, NULL to go to the root folder
 * @param error Place to store error code on failure (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_chdir(GwObex *ctx, const gchar *dir, gint *error);


/** Create a new directory.
 *
 * @param ctx   Pointer returned by gw_obex_setup()
 * @param dir   Directory to create (null terminated UTF-8)
 * @param error Place to store error code on failure (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_mkdir(GwObex *ctx, const gchar *dir, gint *error);


/** Get folder listing for the specified directory.
 *
 * @param ctx      Pointer returned by gw_obex_setup()
 * @param dir      Directory to list (null terminated UTF-8),
 *                 NULL to list current directory
 * @param buf      Place to store the folder-listing object
 * @param buf_size Place to store the size for the retrieved object
 * @param error    Place to store error code on failure (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_read_dir(GwObex *ctx, const gchar *dir,
                          gchar **buf, gint *buf_size, gint *error);


/** Remove a file from the remote device.
 *
 * @param ctx   Pointer returned by gw_obex_setup()
 * @param name  Filename to remove (null terminated UTF-8)
 * @param error Place to store error code on failure (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_delete(GwObex *ctx, const gchar *name, gint *error);


/** Move/Rename a file on the remote device.
 *
 * @param ctx   Pointer returned by gw_obex_setup()
 * @param src   Source filename (null terminated UTF-8)
 * @param dst   Destination filename (null terminated UTF-8)
 * @param error Place to store error code on failure (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_move(GwObex *ctx, const gchar *src, const gchar *dst,
                      gint *error);


/** Copy a file on the remote device.
 *
 * @param ctx   Pointer returned by gw_obex_setup()
 * @param src   Source filename (null terminated UTF-8)
 * @param dst   Destination filename (null terminated UTF-8)
 * @param error Place to store error code on failure (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_copy(GwObex *ctx, const gchar *src, const gchar *dst,
                      gint *error);

/** @} */

/**
 * @name Functions for performing transfers in an asynchronous manner
 * With these functions you can do transfers in smaller steps. The steps
 * are split up in a open, read/write, close manner.
 * @{
 */

/** Start a PUT operation asynchronously
 *
 * @param ctx   Pointer returned by gw_obex_setup()
 * @param name  Name of the object (null terminated UTF-8)
 * @param type  Type of the object (null terminated UTF-8), or NULL
 * @param size  Size of the object (GW_OBEX_UNKNOWN_LENGTH if not known)
 * @param time  Last modification time of the object (-1 if not known)
 * @param error Place to store error code on failure (NULL if not interested)
 *
 * @returns a new GwObexXfer object on success, NULL on failure
 */
GwObexXfer *gw_obex_put_async(GwObex *ctx, const char *name, const char *type,
                              gint size, time_t time, gint *error);


/** Start a GET operation asynchronously
 *
 * @param ctx   Pointer returned by gw_obex_setup()
 * @param name  Name of the object (null terminated UTF-8)
 * @param type  Type of the object (null terminated UTF-8), or NULL
 * @param error Place to store error code on failure (NULL if not interested)
 *
 * @returns a new GwObexXfer object on success, NULL on failure
 */
GwObexXfer *gw_obex_get_async(GwObex *ctx, const char *name, const char *type, gint *error);

/** Start a GET operation asynchronously with application parameters
 *
 * @param ctx   Pointer returned by gw_obex_setup()
 * @param name  Name of the object (null terminated UTF-8)
 * @param type  Type of the object (null terminated UTF-8), or NULL
 * @param apparam      Application parameters of the object
 * @param apparam_size Application paramters' size
 * @param error Place to store error code on failure (NULL if not interested)
 *
 * @returns a new GwObexXfer object on success, NULL on failure
 */

GwObexXfer *gw_obex_get_async_with_apparam(GwObex *ctx, const char *name, const char *type,
		const guint8  *apparam, gint apparam_size, gint *error);


/** Set a callback function for a GwObexXfer object
 * The callback function will be called in the following situations:
 * <ul>
 *  <li>Data can be written (i.e. xfer_write will succeed)</li>
 *  <li>Data can be read (i.e. xfer_read will succees)</li>
 *  <li>An error ocured</li>
 *  <li>The transfer is finished</li>
 * </ul>
 *
 * @param xfer      Pointer returned by gw_obex_put_async or gw_obex_get_async
 * @param cb        Pointer to the callback function
 * @param user_data Optional user data which will be passed to the callback function
 *
 * @returns a new GwObexXfer object on success, NULL on failure
 */
void gw_obex_xfer_set_callback(GwObexXfer *xfer, gw_obex_xfer_cb_t cb, gpointer user_data);


/** Get the last modification time of the object being transfered
 *
 * @param xfer Pointer returned by gw_obex_put_async or gw_obex_get_async
 *
 * @returns The modification time or -1 if it is not known.
 */
time_t gw_obex_xfer_object_time(GwObexXfer *xfer);


/** Get the size of the object being transfered
 *
 * @param xfer Pointer returned by gw_obex_put_async or gw_obex_get_async
 *
 * @returns The size or GW_OBEX_UNKNOWN_LENGTH if it is not known.
 */
gint gw_obex_xfer_object_size(GwObexXfer *xfer);


/** Get the contents of the application parameters header
 *
 * @param xfer Pointer returned by gw_obex_put_async or gw_obex_get_async
 * @param apparam_size Return value for the size of the application parameters header.
 *
 * @returns The pointer to the buffer that hold the contents.
 */
unsigned char *gw_obex_xfer_object_apparam(GwObexXfer *xfer, size_t *apparam_size);


/** Returns if a transfer is already done
 *
 * @param xfer Pointer returned by gw_obex_put_async or gw_obex_get_async
 *
 * @returns whether the current transfer is done
 */
gboolean gw_obex_xfer_object_done(GwObexXfer *xfer);


/** Supply more data to a transfer
 *
 * @param xfer          Pointer returned by gw_obex_put_async or gw_obex_get_async
 * @param buf           Buffer containing the data
 * @param buf_size      Size of the buffer
 * @param bytes_written Return value for the number of bytes that were written
 * @param error Place to store error code on failure (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_xfer_write(GwObexXfer *xfer, const char *buf, gint buf_size,
                            gint *bytes_written, gint *error);

/** Read data from a transfer
 *
 * The function will report EOF by returning success with zero bytes read.
 *
 * @param xfer          Pointer returned by gw_obex_put_async or gw_obex_get_async
 * @param buf           Buffer where the data should be stored
 * @param buf_size      Size of the buffer
 * @param bytes_read    Return value for the number of bytes that were read
 * @param error Place to store error code on failure (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_xfer_read(GwObexXfer *xfer, char *buf, gint buf_size,
                           gint *bytes_read, gint *error);


/** Force all data remaining in buffers to be sent
 *
 * @param xfer  Pointer returned by gw_obex_put_async or gw_obex_get_async
 * @param error Place to store error code on failure (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_xfer_flush(GwObexXfer *xfer, gint *error);


/** Close an ongoing transfer
 *
 * You still need to call gw_obex_xfer_free after this to free the actual
 * memory allocated for the GwObexXfer object.
 *
 * @param xfer  Pointer returned by gw_obex_put_async or gw_obex_get_async
 * @param error Place to store error code on failure (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_xfer_close(GwObexXfer *xfer, gint *error);


/** Abort an ongoing transfer
 *
 * You still need to call gw_obex_xfer_free after this to free the actual
 * memory allocated for the GwObexXfer object. xfer_close and xfer_abort are
 * mutually exclusive (only call one of them for a transfer).
 *
 * @param xfer  Pointer returned by gw_obex_put_async or gw_obex_get_async
 * @param error Place to store error code on failure (NULL if not interested)
 *
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_xfer_abort(GwObexXfer *xfer, gint *error);


/** Free the data allocated for a GwObexXfer object
 *
 * @param xfer  Pointer returned by gw_obex_put_async or gw_obex_get_async
 */
void gw_obex_xfer_free(struct gw_obex_xfer *xfer);


/** Set blocking behaviour for a GwObexXfer object when calling xfer_read and xfer_write
 *
 * When blocking is enabled xfer_read will return only after it has been able
 * to read some data (i.e. GW_OBEX_ERROR_NO_DATA will not be returned). For xfer_write
 * blocking guarantees that *some* data will be written.
 *
 * @param xfer  Pointer returned by gw_obex_put_async or gw_obex_get_async
 * @param block TRUE to enable blocking behaviour
 */
void gw_obex_xfer_set_blocking(GwObexXfer *xfer, gboolean block);

/** @} */

#endif /* _GW_OBEX_H_ */


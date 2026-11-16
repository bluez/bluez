/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#define EOL	"\r\n"
#define VCARD_LISTING_BEGIN \
	"<?xml version=\"1.0\"?>" EOL\
	"<!DOCTYPE vcard-listing SYSTEM \"vcard-listing.dtd\">" EOL\
	"<vCard-listing version=\"1.0\">" EOL
#define VCARD_LISTING_ELEMENT "<card handle = \"%d.vcf\" name = \"%s\"/>" EOL
#define VCARD_LISTING_END "</vCard-listing>"

#define PB_TELECOM_FOLDER "/telecom"
#define PB_CONTACTS_FOLDER "/telecom/pb"
#define PB_CALENDAR_FOLDER "/telecom/cal"
#define PB_NOTES_FOLDER "/telecom/nt"
#define PB_CALLS_COMBINED_FOLDER "/telecom/cch"
#define PB_CALLS_INCOMING_FOLDER "/telecom/ich"
#define PB_CALLS_MISSED_FOLDER "/telecom/mch"
#define PB_CALLS_OUTGOING_FOLDER "/telecom/och"
#define PB_CALLS_SPEEDDIAL_FOLDER "/telecom/spd"
#define PB_CALLS_FAVORITE_FOLDER "/telecom/fav"
#define PB_LUID_FOLDER "/telecom/pb/luid"

#define PB_CONTACTS "/telecom/pb.vcf"
#define PB_CALLS_COMBINED "/telecom/cch.vcf"
#define PB_CALLS_INCOMING "/telecom/ich.vcf"
#define PB_CALLS_MISSED "/telecom/mch.vcf"
#define PB_CALLS_OUTGOING "/telecom/och.vcf"
#define PB_CALLS_SPEEDDIAL "/telecom/spd.vcf"
#define PB_CALLS_FAVORITE "/telecom/fav.vcf"
#define PB_DEVINFO "/telecom/devinfo.txt"
#define PB_INFO_LOG "/telecom/pb/info.log"
#define PB_CC_LOG "/telecom/pb/luid/cc.log"

#define PRIMARY_COUNTER "primary_counter"
#define SECONDARY_COUNTER "secondary_counter"

struct apparam_field {
	/* list and pull attributes */
	uint16_t maxlistcount;
	uint16_t liststartoffset;

	/* pull and vcard attributes */
	uint64_t filter;
	uint8_t format;

	/* list attributes only */
	uint8_t order;
	uint8_t searchattrib;
	char *searchval;

	/* vCard Selecting attributes */
	uint64_t selector;
	uint8_t selector_operator;
};

/* Metadata identifying the current database contents. */
struct phonebook_metadata {
	uint8_t database_identifier[16];
	uint8_t primary_counter[16];
	uint8_t secondary_counter[16];
};

/*
 * Interface between the PBAP core and backends to retrieve
 * all contacts that match the application parameters rules.
 * Contacts will be returned in the vcard format.
 */
typedef void (*phonebook_cb) (const char *buffer, size_t bufsize,
		int vcards, uint8_t missed, gboolean lastpart, void *user_data);

/*
 * Interface between the PBAP core and backends to
 * append a new entry in the PBAP folder cache.
 *
 * mask is a bitmask of the vCard properties holding a value for this
 * entry, using the bit assignment of the vCardSelector.
 */
#define PHONEBOOK_INVALID_HANDLE 0xffffffff
typedef void (*phonebook_entry_cb) (const char *id, uint32_t handle,
					const char *name, const char *sound,
					const char *tel, uint64_t mask,
					void *user_data);

/* Notifies cache completion and the number of undismissed missed calls. */
typedef void (*phonebook_cache_ready_cb) (uint8_t missed, void *user_data);

/* vCardSelector property names, indexed by bit number. */
static const char * const phonebook_selector_properties[] = {
/* 0 */	"VERSION",
	"FN",
	"N",
	"PHOTO",
	"BDAY",
	"ADR",
	"LABEL",
	"TEL",
/* 8 */	"EMAIL",
	"MAILER",
	"TZ",
	"GEO",
	"TITLE",
	"ROLE",
	"LOGO",
	"AGENT",
/* 16 */	"ORG",
	"NOTE",
	"REV",
	"SOUND",
	"URL",
	"UID",
	"KEY",
	"NICKNAME",
/* 24 */	"CATEGORIES",
	"PRODID",
	"CLASS",
	"SORT-STRING",
/* 28 */	"X-IRMC-CALL-DATETIME",
	"X-BT-SPEEDDIALKEY",
	"X-BT-UCI",
	"X-BT-UID"
};

/*
 * A zero selector matches all entries. Bit 0 of the operator selects
 * AND (1) or OR (0).
 */
static inline gboolean phonebook_selector_match(uint64_t mask,
				uint64_t selector, uint8_t selector_operator)
{
	/* Ignore reserved property bits. */
	selector &= ~(0x7fULL << 32);

	if (!selector)
		return TRUE;

	if (selector_operator & 0x01)
		return (mask & selector) == selector;

	return (mask & selector) != 0;
}


/*
 * Set up and tear down the phonebook back-end. The back-end is shared by
 * the pbap and the irmc plugin, which are loaded and unloaded independently
 * of each other, so the calls are reference counted: only the first
 * phonebook_init() and the last phonebook_exit() reach the back-end.
 */
int phonebook_init(void);
void phonebook_exit(void);

/* Implemented by the back-end, only called through the pair above. */
int phonebook_driver_init(void);
void phonebook_driver_exit(void);

/*
 * Changes the current folder in the phonebook back-end. The PBAP core
 * doesn't validate or restrict the possible values for the folders,
 * allowing non-standard backends implementation which doesn't follow
 * the PBAP virtual folder architecture. Validate the folder's name
 * is responsibility of the back-ends.
*/
char *phonebook_set_folder(const char *current_folder,
		const char *new_folder, uint8_t flags, int *err);

/*
 * Returns the metadata identifying the current database contents. A zero
 * database identifier means the values are not persistent.
 */
int phonebook_get_metadata(const char *folder,
					struct phonebook_metadata *metadata);

/*
 * phonebook_pull should be used only to prepare pull request - prepared
 * request data is returned by this function. Start of fetching data from
 * back-end will be done only after calling phonebook_pull_read with this
 * returned request given as a parameter.
 *
 * phonebook_req_finalize MUST always be used to free associated resources.
 */
void *phonebook_pull(const char *name, const struct apparam_field *params,
				phonebook_cb cb, void *user_data, int *err);

/*
 * phonebook_pull_read should be used to start getting results from back-end.
 * The back-end can return data as one response or can return it many parts.
 * After obtaining one part, PBAP core need to call phonebook_pull_read with
 * the same request again to get more results from back-end.
 * The back-end MUST return only the content based on the application
 * parameters requested by the client.
 *
 * Returns error code or 0 in case of success
 */
int phonebook_pull_read(void *request);

/*
 * Function used to retrieve a contact from the backend. Only contacts
 * found in the cache are requested to the back-ends. The back-end MUST
 * return only the content based on the application parameters requested
 * by the client.
 *
 * Return value is a pointer to asynchronous request to phonebook back-end.
 * phonebook_req_finalize MUST always be used to free associated resources.
 */
void *phonebook_get_entry(const char *folder, const char *id,
				const struct apparam_field *params,
				phonebook_cb cb, void *user_data, int *err);

/*
 * PBAP core will keep the contacts cache per folder. SetPhoneBook or
 * PullvCardListing can invalidate the cache if the current folder changes.
 * Cache will store only the necessary information required to reply to
 * PullvCardListing request and verify if a given contact belongs to the
 * source.
 *
 * Return value is a pointer to asynchronous request to phonebook back-end.
 * phonebook_req_finalize MUST always be used to free associated resources.
 */
void *phonebook_create_cache(const char *name, phonebook_entry_cb entry_cb,
		phonebook_cache_ready_cb ready_cb, void *user_data, int *err);

/*
 * Finalizes request to phonebook back-end and deallocates associated
 * resources. Operation is canceled if not completed. This function MUST
 * always be used after any of phonebook_pull, phonebook_get_entry, and
 * phonebook_create_cache invoked.
 *
 * request is a pointer to asynchronous operation returned by phonebook_pull,
 * phonebook_get_entry, and phonebook_create_cache.
 */
void phonebook_req_finalize(void *request);

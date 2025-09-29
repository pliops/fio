/*
 * storelib engine
 *
 * IO engine that uses Pliops Storelib to perform KV IOs
 *
 */
#include <stdlib.h>
#include <unistd.h>
#include <sys/uio.h>
#include <errno.h>
#include <stdint.h>
#include <store_lib_expo.h>

#include "../fio.h"
#include "../optgroup.h"
#include "../lib/rand.h"

/*
 * Sync engine uses engine_data to store last offset
 */
#define LAST_POS(f)	((f)->engine_pos)

struct storelib_options {
	void *pad;
	unsigned int tail_size_in_bytes;
	bool create_if_missing;
	bool error_if_exists;
	int stream_id;
	bool skip_size_verification;
	bool use_offset_as_key;
};

static struct fio_option options[] = {
	{
		.name = "tail_size_bytes",
		.lname = "tail size bytes",
		.help = "Tail size in bytes",
		.type = FIO_OPT_INT,
		.off1 = offsetof(struct storelib_options, tail_size_in_bytes),
		.def = "0",
		.category = FIO_OPT_C_IO,
	},
	{
		.name = "create_if_missing",
		.lname = "create if missing",
		.help = "Create the DB if isn't already open",
		.type = FIO_OPT_BOOL,
		.off1 = offsetof(struct storelib_options, create_if_missing),
		.def = "1",
		.category = FIO_OPT_C_FILE,
	},
	{
		.name = "error_if_exists",
		.lname = "error if exists",
		.help = "Fail open if DB already exists",
		.type = FIO_OPT_BOOL,
		.off1 = offsetof(struct storelib_options, error_if_exists),
		.def = "0",
		.category = FIO_OPT_C_FILE,
	},
	{
		.name = "stream_id",
		.lname = "stream ID",
		.help = "StreamID input for splitting data to streams",
		.type = FIO_OPT_INT,
		.off1 = offsetof(struct storelib_options, stream_id),
		.def = "0",
		.category = FIO_OPT_C_IO,
	},
	{
		.name = "skip_size_verification",
		.lname = "Skip size verification",
		.help = "Skip object size verification in gets",
		.type = FIO_OPT_BOOL,
		.off1 = offsetof(struct storelib_options, skip_size_verification),
		.def = "0",
		.category = FIO_OPT_C_IO,
	},
	{
		.name = "use_offset_as_key",
		.lname = "Use offset as key",
		.help = "Use the IO offset as the object key",
		.type = FIO_OPT_BOOL,
		.off1 = offsetof(struct storelib_options, use_offset_as_key),
		.def = "0",
		.category = FIO_OPT_C_IO,
	},
	{
		.name = NULL,
	},
};

static PLIOPS_STATUS_et storelib_get(PLIOPS_DB_t db, struct io_u *io_u, bool skip_size_verification, bool use_offset_as_key)
{
	PLIOPS_STATUS_et status;
	unsigned int actualSize = 0;
	unsigned long long key = use_offset_as_key ? io_u->offset : io_u->offset / io_u->xfer_buflen;

	status = PLIOPS_Get(db, &key, sizeof(io_u->offset), io_u->xfer_buf, io_u->xfer_buflen, &actualSize);
	if (status != PLIOPS_STATUS_OK) {
		if (status == PLIOPS_STATUS_NON_EXIST) {
			return PLIOPS_STATUS_OK;
		}

		log_err("storelib: Get failed with %d\n", status);
		return status;
	}

	if (!skip_size_verification && (actualSize != io_u->xfer_buflen)) {
		log_err("storelib: Unexpected object size (expected %llu, got %u)\n", io_u->xfer_buflen, actualSize);
		return PLIOPS_STATUS_INCOMPLETE;
	}

	return PLIOPS_STATUS_OK;
}

static PLIOPS_STATUS_et storelib_put(PLIOPS_DB_t db, struct io_u *io_u, bool use_offset_as_key)
{
	PLIOPS_STATUS_et status;
	unsigned long long key = use_offset_as_key ? io_u->offset : io_u->offset / io_u->xfer_buflen;

	status = PLIOPS_Put(db, &key, sizeof(io_u->offset), io_u->xfer_buf, io_u->xfer_buflen, 0);
	if (status != PLIOPS_STATUS_OK) {
		log_err("storelib: Put failed with %d\n", status);
		return status;
	}

	return status;
}

static PLIOPS_STATUS_et storelib_delete(PLIOPS_DB_t db, struct io_u *io_u, bool use_offset_as_key)
{
	PLIOPS_STATUS_et status;
	unsigned long long key = use_offset_as_key ? io_u->offset : io_u->offset / io_u->xfer_buflen;

	status = PLIOPS_Delete(db, &key, sizeof(io_u->offset), 0);
	if (status != PLIOPS_STATUS_OK) {
		log_err("storelib: Delete failed with %d\n", status);
	}

	return status;
}

static PLIOPS_STATUS_et storelib_flush_cache(PLIOPS_DB_t db)
{
	PLIOPS_STATUS_et status;

	status = PLIOPS_Flush(db);
	if (status != PLIOPS_STATUS_OK) {
		log_err("storelib: Flush failed with %d\n", status);
	}

	return status;}

static enum fio_q_status storelib_queue(struct thread_data *td, struct io_u *io_u)
{
	PLIOPS_STATUS_et status;
	const struct storelib_options *eo = td->eo;

	switch (io_u->ddir) {
	case DDIR_READ:
		status = storelib_get(io_u->file->fd, io_u, eo->skip_size_verification, eo->use_offset_as_key);
		break;
	case DDIR_WRITE:
		status = storelib_put(io_u->file->fd, io_u, eo->use_offset_as_key);
		break;
	case DDIR_TRIM:
		status = storelib_delete(io_u->file->fd, io_u, eo->use_offset_as_key);
		break;
	case DDIR_SYNC:
	case DDIR_DATASYNC:
		status = storelib_flush_cache(io_u->file->fd);
		break;
	case DDIR_SYNC_FILE_RANGE:
	case DDIR_WAIT:
	default:
		log_err("storelib: unsupported ddir %u\n", io_u->ddir);
		status = PLIOPS_STATUS_NOT_SUPPORTED;
	};

	if (status != PLIOPS_STATUS_OK) {
		io_u->error = EIO;
		io_u_log_error(td, io_u);
		td_verror(td, io_u->error, "xfer");
	} else if (ddir_rw(io_u->ddir)) {
		LAST_POS(io_u->file) = io_u->offset + io_u->offset;
	}

	return FIO_Q_COMPLETED;
}

static int storelib_parse_filename(const char *filename, int *xdp, PLIOPS_IDENTIFY_t *db)
{
	int retval = 0;

	if (sscanf(filename, "xdp%udb%lu", xdp, db) != 2) {
		log_err("Failed to parse filename '%s': expected format 'xdp<XDP_ID>db<DB_ID>'\n", filename);
		return EINVAL;
	}

	return retval;
}

static int storelib_open_file(struct thread_data *td, struct fio_file *f)
{
	PLIOPS_STATUS_et status;
	const struct storelib_options *eo = td->eo;
	int rv, xdpId;
	PLIOPS_IDENTIFY_t db_id;
	PLIOPS_DB_t db_handle;
	PLIOPS_DB_OPEN_OPTIONS_t opts = {
		.tailSizeInBytes = eo->tail_size_in_bytes,
		.createIfMissing = eo->create_if_missing,
		.errorIfExists = eo->error_if_exists,
		.streamId = eo->stream_id,
		.exportDbIngestOnlyMode = false,
	};

	f->fd = -1;

	rv = storelib_parse_filename(f->file_name, &xdpId, &db_id);
	if (rv) {
		return rv;
	}

	status = PLIOPS_OpenDB(db_id, &opts, xdpId, &db_handle);
	if (status != PLIOPS_STATUS_OK) {
		log_err("storelib: Failed to open DB %lu on XDP %u: Pliops status: %d\n",
				db_id, xdpId, status);
		return 1;
	}

	f->fd = db_handle;

	return 0;
}

static int storelib_close_file(struct thread_data *td, struct fio_file *f)
{
	PLIOPS_STATUS_et status;
	int rv;

	status = PLIOPS_CloseDB(f->fd);
	if (status != PLIOPS_STATUS_OK) {
		log_err("storelib: Failed to close DB: Pliops status: %d\n", status);
		rv = 1;
	}

	f->fd = -1;

	return rv;
}

static int storelib_get_file_size(struct thread_data *td, struct fio_file *f)
{
	PLIOPS_STATUS_et status;
	int ret, xdpId;
	PLIOPS_IDENTIFY_t db_id;
	PLIOPS_CAPACITY_USAGE_INFO_t capacity;

	ret = storelib_parse_filename(f->file_name, &xdpId, &db_id);
	if (ret) {
		return ret;
	}

	status = PLIOPS_GetCapacityUsage(xdpId, &capacity);
	if (status != PLIOPS_STATUS_OK) {
		log_err("storelib: Failed to get capacity for XDP %u. Pliops status: %d\n", xdpId, status);
		return 1;
	}

	f->real_file_size = capacity.physicalDiskSpaceInBytes;

	return 0;
}

static int storelib_invalidate(struct thread_data *td, struct fio_file *f)
{
	return storelib_flush_cache(f->fd);
}

static struct ioengine_ops ioengine_storelib = {
	.name                = "storelib",
	.version             = FIO_IOOPS_VERSION,
	.open_file           = storelib_open_file,
	.close_file          = storelib_close_file,
	.get_file_size       = storelib_get_file_size,
	.invalidate          = storelib_invalidate,
	.queue               = storelib_queue,
	.flags               = FIO_SYNCIO | FIO_DISKLESSIO,
	.options             = options,
	.option_struct_size  = sizeof(struct storelib_options),
};

static void fio_init fio_syncio_register(void)
{
	register_ioengine(&ioengine_storelib);
}

static void fio_exit fio_syncio_unregister(void)
{
	unregister_ioengine(&ioengine_storelib);
}

/*
* lightning_kv_nvme I/O engine
*
* IO engine using NVMe vendor-specific commands via ioctls
* for KV storage acceleration.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/nvme_ioctl.h>

#include "nvme.h"
#include "../fio.h"
#include "../optgroup.h"

static const uint32_t g_lightning_kv_nvme_database_identifier = 0;

enum LIGHTNING_NVME_OPCODE {
    LIGHTNING_NVME_OPCODE_PUT       = 0x81,
    LIGHTNING_NVME_OPCODE_GET       = 0x82,
    LIGHTNING_NVME_OPCODE_EXIST     = 0x84,
    LIGHTNING_NVME_OPCODE_DELETE    = 0x88,
    LIGHTNING_NVME_OPCODE_OPEN_DB   = 0xC4,
    LIGHTNING_NVME_OPCODE_CLOSE_DB  = 0xC8,
    LIGHTNING_NVME_OPCODE_DELETE_DB = 0xCC,
};

/* Engine options */
struct lightning_kv_nvme_options {
    void *pad;  /* not used */
};

/* Engine data */
struct lightning_kv_nvme_data {
    struct lightning_kv_nvme_options options;
};

/* Option list */
static struct fio_option options[] = {
    {
        .name = NULL,
    },
};

/* Initialize the engine */
static int fio_lightning_kv_nvme_init(struct thread_data *td)
{
    struct lightning_kv_nvme_data *pkd;

    pkd = calloc(1, sizeof(struct lightning_kv_nvme_data));
    if (!pkd) {
        td_verror(td, errno, "calloc");
        return ENOMEM;
    }

    td->io_ops_data = pkd;
    return 0;
}

// static int fio_lightning_kv_nvme_identify(struct fio_file *f)
// {
//     struct nvme_admin_cmd cmd;
//     struct nvme_id_ctrl ctrl;
//     int ret;

//     memset(&cmd, 0, sizeof(cmd));
//     memset(&ctrl, 0, sizeof(ctrl));

//     cmd.opcode = nvme_admin_identify;
//     cmd.nsid = 0;
//     cmd.addr = (uint64_t)&ctrl;
//     cmd.data_len = NVME_IDENTIFY_DATA_SIZE;
//     cmd.cdw10 = NVME_IDENTIFY_CNS_CTRL;

//     ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
//     if (ret < 0) {
//         log_err("Failed to NVMe Identify command\n");
//         return 1;
//     }

//     log_err("ctrl.mdts=0x%x\n", ctrl.mdts);

//     return 0;
// }

static int fio_lightning_kv_send_nvme_command(int fd, uint8_t opcode, const void *data, uint32_t data_len, void *value, uint32_t value_len, unsigned long ioctl_cmd)
{
    int ret;
    uint64_t data_uint64 = 0;
    struct nvme_passthru_cmd64 cmd = {
        .opcode = opcode,
        .nsid = 1,  // Using default namespace 1
        .addr = (uint64_t)value,
        .data_len = value_len,
    };

    switch (data_len) {
    case (sizeof(uint32_t)):
        data_uint64 = *(uint32_t*)data;
        break;
    case (sizeof(uint64_t)):
        data_uint64 = *(uint64_t*)data;
        break;
    default:
        log_err("Unsupported command data len %u\n", data_len);
        return EINVAL;
    }

    memcpy(&cmd.cdw12, data, data_len);

    ret = ioctl(fd, ioctl_cmd, &cmd);

    // Check the NVMe status code
    if ((cmd.result) || (ret != 0)) {
        log_err("NVMe cmd failed: ret=%d, opcode=0x%x, data=0x%" PRIx64 ", result=0x%llx, errno=%d\n",
                ret, opcode, data_uint64, cmd.result, errno);
        return EIO;
    }

    return ret;
}

static int fio_lightning_kv_nvme_open(struct thread_data *td, struct fio_file *f)
{
    int ret, ret_close_file;

    ret = generic_open_file(td, f);
    if (ret != 0) {
        return ret;
    }

    ret = fio_lightning_kv_send_nvme_command(f->fd, LIGHTNING_NVME_OPCODE_OPEN_DB,
                                             &g_lightning_kv_nvme_database_identifier, sizeof(g_lightning_kv_nvme_database_identifier),
                                             NULL, 0, NVME_IOCTL_ADMIN_CMD);
    if (ret) {
        log_err("Failed to open DB %u: %d\n", g_lightning_kv_nvme_database_identifier, ret);

        /* FIO warns if we do not use the return value of generic_close_file() */
        ret_close_file = generic_close_file(td, f);
        if (ret_close_file) {
            log_err("generic_close_file failed with %d", ret_close_file);
        }
    }

    return ret;
}

static int fio_lightning_kv_nvme_close(struct thread_data *td, struct fio_file *f)
{
    int ret_close_db, ret_close;

    ret_close_db = fio_lightning_kv_send_nvme_command(f->fd, LIGHTNING_NVME_OPCODE_CLOSE_DB,
                                             &g_lightning_kv_nvme_database_identifier, sizeof(g_lightning_kv_nvme_database_identifier),
                                             NULL, 0, NVME_IOCTL_ADMIN_CMD);
    if (ret_close_db) {
        log_err("Failed to close DB %u: %d\n", g_lightning_kv_nvme_database_identifier, ret_close_db);
    }

    ret_close = generic_close_file(td, f);

    return ret_close_db ? ret_close_db : ret_close;
}

static enum fio_q_status fio_lightning_kv_nvme_queue(struct thread_data *td, struct io_u *io_u)
{
    int ret;

    fio_ro_check(td, io_u);

    switch (io_u->ddir) {
    case DDIR_WRITE:
        /* Perform KV PUT operation */
        ret = fio_lightning_kv_send_nvme_command(io_u->file->fd, LIGHTNING_NVME_OPCODE_PUT, &io_u->offset,
                                              sizeof(io_u->offset), io_u->xfer_buf, io_u->xfer_buflen, NVME_IOCTL_IO64_CMD);
        break;
    case DDIR_READ:
        /* Perform KV GET operation */
        ret = fio_lightning_kv_send_nvme_command(io_u->file->fd, LIGHTNING_NVME_OPCODE_GET, &io_u->offset,
                                              sizeof(io_u->offset), io_u->xfer_buf, io_u->xfer_buflen, NVME_IOCTL_IO64_CMD);
        break;
    case DDIR_TRIM:
        /* Perform KV DELETE operation */
        ret = fio_lightning_kv_send_nvme_command(io_u->file->fd, LIGHTNING_NVME_OPCODE_DELETE, &io_u->offset,
                                                sizeof(io_u->offset), NULL, 0, NVME_IOCTL_IO64_CMD);
        break;
    default:
        log_err("lightning_kv_nvme: unsupported I/O operation %d\n", io_u->ddir);
        io_u->error = EINVAL;
        return FIO_Q_COMPLETED;
    }

    if (ret) {
        io_u->error = EIO;
    }

    return FIO_Q_COMPLETED;
}

/* Clean up the engine */
static void fio_lightning_kv_nvme_cleanup(struct thread_data *td)
{
    struct lightning_kv_nvme_data *pkd = td->io_ops_data;

    if (pkd) {
        free(pkd);
        td->io_ops_data = NULL;
    }
}

/* FIO engine structure */
static struct ioengine_ops ioengine_lightning_kv_nvme = {
    .name           = "lightning_kv_nvme",
    .version        = FIO_IOOPS_VERSION,
    .init           = fio_lightning_kv_nvme_init,
    .queue          = fio_lightning_kv_nvme_queue,
    .open_file      = fio_lightning_kv_nvme_open,
    .close_file     = fio_lightning_kv_nvme_close,
    .cleanup        = fio_lightning_kv_nvme_cleanup,
    .get_file_size  = generic_get_file_size,
    .options        = options,
    .option_struct_size = sizeof(struct lightning_kv_nvme_options),
    .flags          = FIO_SYNCIO | FIO_DISKLESSIO,
};

/* Register this engine with FIO */
static void fio_init fio_lightning_kv_nvme_register(void)
{
    register_ioengine(&ioengine_lightning_kv_nvme);
}

/* Unregister the engine when unloading */
static void fio_exit fio_lightning_kv_nvme_unregister(void)
{
    unregister_ioengine(&ioengine_lightning_kv_nvme);
}

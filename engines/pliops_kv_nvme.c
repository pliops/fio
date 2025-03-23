/*
* pliops_kv_nvme I/O engine
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

/* NVMe vendor-specific command opcodes - these would be specific to your device */
#define PLIOPS_NVME_OPCODE_GET 0x82  /* NVMe opcode for Pliops GET operation */
#define PLIOPS_NVME_OPCODE_PUT 0x81  /* NVMe opcode for Pliops PUT operation */

/* Engine options */
struct pliops_kv_nvme_options {
    void *pad;  /* not used */
};

/* Engine data */
struct pliops_kv_nvme_data {
    struct pliops_kv_nvme_options options;
};

/* Option list */
static struct fio_option options[] = {
    {
        .name = NULL,
    },
};

/* Initialize the engine */
static int fio_pliops_kv_nvme_init(struct thread_data *td)
{
    struct pliops_kv_nvme_data *pkd;

    pkd = calloc(1, sizeof(struct pliops_kv_nvme_data));
    if (!pkd) {
        td_verror(td, errno, "calloc");
        return ENOMEM;
    }

    td->io_ops_data = pkd;
    return 0;
}

// static int fio_pliops_kv_nvme_identify(struct fio_file *f)
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

static int fio_pliops_kv_nvme_open(struct thread_data *td, struct fio_file *f)
{
    return generic_open_file(td, f);
}

static int fio_pliops_kv_nvme_close(struct thread_data *td, struct fio_file *f)
{
    return generic_close_file(td, f);
}

static int fio_pliops_kv_send_nvme_command(int fd, uint8_t opcode, void *key, uint32_t key_len, void *value, uint32_t value_len)
{
    int ret;

    struct nvme_passthru_cmd64 cmd = {
        .opcode = opcode,
        .nsid = 1,  // Using default namespace 1
        .addr = (uint64_t)value,
        .data_len = value_len,
    };
    memcpy(&cmd.cdw12, key, key_len);

    ret = ioctl(fd, NVME_IOCTL_IO64_CMD, &cmd);

    // Check the NVMe status code
    if ((cmd.result) || (ret != 0)) {
        log_err("NVMe cmd failed: ret=%d, opcode=0x%x, key=0x%" PRIx64 ", result=0x%llx, errno=%d\n",
                ret, opcode, *(uint64_t *)key, cmd.result, errno);
        return EIO;
    }

    return ret;
}

static enum fio_q_status fio_pliops_kv_nvme_queue(struct thread_data *td, struct io_u *io_u)
{
    int ret;

    fio_ro_check(td, io_u);

    switch (io_u->ddir) {
    case DDIR_WRITE:
        /* Perform KV PUT operation */
        ret = fio_pliops_kv_send_nvme_command(io_u->file->fd, PLIOPS_NVME_OPCODE_PUT, &io_u->offset,
                                              sizeof(io_u->offset), io_u->xfer_buf, io_u->xfer_buflen);
        break;
    case DDIR_READ:
        /* Perform KV GET operation */
        ret = fio_pliops_kv_send_nvme_command(io_u->file->fd, PLIOPS_NVME_OPCODE_GET, &io_u->offset,
                                              sizeof(io_u->offset), io_u->xfer_buf, io_u->xfer_buflen);
        break;
    default:
        log_err("pliops_kv_nvme: unsupported I/O operation %d\n", io_u->ddir);
        io_u->error = EINVAL;
        return FIO_Q_COMPLETED;
    }

    if (ret) {
        io_u->error = EIO;
    }

    return FIO_Q_COMPLETED;
}

/* Clean up the engine */
static void fio_pliops_kv_nvme_cleanup(struct thread_data *td)
{
    struct pliops_kv_nvme_data *pkd = td->io_ops_data;

    if (pkd) {
        free(pkd);
        td->io_ops_data = NULL;
    }
}
static int fio_pliops_kv_nvme_get_file_size(struct thread_data *td, struct fio_file *f)
{
    if (fio_file_size_known(f)) {
        return 0;
    }

    // Set the device size as max as possible
    f->real_file_size = UINT64_MAX;
    fio_file_set_size_known(f);

    // TODO: support max object size
    // fio_pliops_kv_nvme_identify(f);

    return 0;
}


/* FIO engine structure */
static struct ioengine_ops ioengine_pliops_kv_nvme = {
    .name           = "pliops_kv_nvme",
    .version        = FIO_IOOPS_VERSION,
    .init           = fio_pliops_kv_nvme_init,
    .queue          = fio_pliops_kv_nvme_queue,
    .open_file      = fio_pliops_kv_nvme_open,
    .close_file     = fio_pliops_kv_nvme_close,
    .cleanup        = fio_pliops_kv_nvme_cleanup,
    .get_file_size  = fio_pliops_kv_nvme_get_file_size,
    .options        = options,
    .option_struct_size = sizeof(struct pliops_kv_nvme_options),
    .flags          = FIO_SYNCIO | FIO_DISKLESSIO,
};

/* Register this engine with FIO */
static void fio_init fio_pliops_kv_nvme_register(void)
{
    register_ioengine(&ioengine_pliops_kv_nvme);
}

/* Unregister the engine when unloading */
static void fio_exit fio_pliops_kv_nvme_unregister(void)
{
    unregister_ioengine(&ioengine_pliops_kv_nvme);
}

#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "op1w4k.skel.h"

char target_rdesc[] = {
    0x05, 0x01,        // Usage Page (Generic Desktop Ctrls)
    0x09, 0x06,        // Usage (Keyboard)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x02,        //   Report ID (2)
    0x05, 0x07,        //   Usage Page (Kbrd/Keypad)
    0x19, 0xE0,        //   Usage Minimum (0xE0)
    0x29, 0xE7,        //   Usage Maximum (0xE7)
    0x15, 0x00,        //   Logical Minimum (0)
    0x25, 0x01,        //   Logical Maximum (1)
    0x75, 0x01,        //   Report Size (1)
    0x95, 0x08,        //   Report Count (8)
    0x81, 0x02,        //   Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x95, 0x01,        //   Report Count (1)
    0x75, 0x08,        //   Report Size (8)
    0x81, 0x01,        //   Input (Const,Array,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x95, 0x05,        //   Report Count (5)
    0x75, 0x08,        //   Report Size (8)
    0x15, 0x00,        //   Logical Minimum (0)
    0x25, 0x65,        //   Logical Maximum (101)
    0x05, 0x07,        //   Usage Page (Kbrd/Keypad)
    0x19, 0x01,        //   Usage Minimum (0x01)
    0x29, 0x65,        //   Usage Maximum (0x65)
    0x81, 0x00,        //   Input (Data,Array,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0xC0,              // End Collection
    0x06, 0x01, 0xFF,  // Usage Page (Vendor Defined 0xFF01)
    0x09, 0x02,        // Usage (0x02)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0xA1,        //   Report ID (-95)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x3F,        //   Report Count (63)
    0x15, 0x00,        //   Logical Minimum (0)
    0x25, 0x01,        //   Logical Maximum (1)
    0x09, 0x21,        //   Usage (0x21)
    0xB1, 0x03,        //   Feature (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0x85, 0xA0,        //   Report ID (-96)
    0x75, 0x80,        //   Report Size (-128)
    0x95, 0x41,        //   Report Count (65)
    0x15, 0x00,        //   Logical Minimum (0)
    0x25, 0x01,        //   Logical Maximum (1)
    0x09, 0x22,        //   Usage (0x22)
    0xB1, 0x03,        //   Feature (Const,Var,Abs,No Wrap,Linear,Preferred State,No Null Position,Non-volatile)
    0xC0,              // End Collection
    0x05, 0x0C,        // Usage Page (Consumer)
    0x09, 0x01,        // Usage (Consumer Control)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x06,        //   Report ID (6)
    0x19, 0x01,        //   Usage Minimum (Consumer Control)
    0x2A, 0x3C, 0x02,  //   Usage Maximum (AC Format)
    0x15, 0x01,        //   Logical Minimum (1)
    0x26, 0x3C, 0x02,  //   Logical Maximum (572)
    0x95, 0x01,        //   Report Count (1)
    0x75, 0x10,        //   Report Size (16)
    0x81, 0x00,        //   Input (Data,Array,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0xC0,              // End Collection
    0x06, 0x02, 0xFF,  // Usage Page (Vendor Defined 0xFF02)
    0x09, 0x01,        // Usage (0x01)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x03,        //   Report ID (3)
    0x19, 0x01,        //   Usage Minimum (0x01)
    0x29, 0xFF,        //   Usage Maximum (0xFF)
    0x15, 0x00,        //   Logical Minimum (0)
    0x25, 0x00,        //   Logical Maximum (0)
    0x95, 0x07,        //   Report Count (7)
    0x75, 0x08,        //   Report Size (8)
    0x81, 0x01,        //   Input (Const,Array,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0xC0,              // End Collection
    0x06, 0x02, 0xFF,  // Usage Page (Vendor Defined 0xFF02)
    0x09, 0x02,        // Usage (0x02)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x08,        //   Report ID (8)
    0x19, 0x01,        //   Usage Minimum (0x01)
    0x29, 0xFF,        //   Usage Maximum (0xFF)
    0x15, 0x00,        //   Logical Minimum (0)
    0x25, 0x00,        //   Logical Maximum (0)
    0x95, 0x3F,        //   Report Count (63)
    0x75, 0x08,        //   Report Size (8)
    0x81, 0x01,        //   Input (Const,Array,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0xC0,              // End Collection

    // 156 bytes
};

/*
 * Given a path like "/sys/bus/hid/devices/0003:3367:1970.0049", check the vid/pid and report
 * descriptor
 */
bool device_matches(const char* sysfs_path) {

    /* Check path */
    if (strlen(sysfs_path) != 40) {
        return false;
    }

    const char prefix[] = "/sys/bus/hid/devices/";
    if (strncmp(prefix, sysfs_path, sizeof(prefix) - 1) != 0) {
        return false;
    }

    const char vid_pid[] = "3367:1970";
    if (strncmp(vid_pid, sysfs_path + 26, sizeof(vid_pid) - 1) != 0) {
        return false;
    }

    char pathbuf[40 + 18 + 1];
    snprintf(pathbuf, sizeof(pathbuf), "%s/report_descriptor", sysfs_path);

    /* Check report descriptor */
    int fd = open(pathbuf, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "Failed to open %s: %s\n", pathbuf, strerror(errno));
        return false;
    }

    char reportbuf[sizeof(target_rdesc) + 1];
    int bytes_read = read(fd, &reportbuf, sizeof(reportbuf));
    close(fd);
    if (bytes_read == -1) {
        fprintf(stderr, "Failed to read %s: %s\n", pathbuf, strerror(errno));
        return false;
    }
    if (bytes_read != sizeof(target_rdesc)) {
        return false;
    }

    if (memcmp(reportbuf, target_rdesc, sizeof(target_rdesc)) != 0) {
        return false;
    }

    return true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

volatile char signaled = 0;
void signal_handler(int sig) {
    signaled = 1;
}

int attach_bpf(int hid_id);
int main(int argc, char *argv[]) {
    char *dirpath = "/sys/bus/hid/devices/";
    DIR *d = opendir(dirpath);
    struct dirent *ent = NULL;
    errno = 0;
    bool attached = false;
    while ((errno = 0, ent = readdir(d)) != NULL) {
        if (errno != 0) {
            fprintf(stderr, "Failed to read directory %s: %s\n", dirpath, strerror(errno));
            continue;
        }
        if (ent->d_name[0] == '.') {
            continue;
        }

        char devbuf[41];
        snprintf(devbuf, sizeof(devbuf), "%s%s", dirpath, ent->d_name);
        if (!device_matches(devbuf)) {
            continue;
        }

        fprintf(stderr, "%s matches, attaching eBPF program\n", devbuf);

        int hid_id = strtol(devbuf + 36, NULL, 16);
        if (attach_bpf(hid_id) == 0) {
            attached = true;
        }
    }

    if (attached) {
        for (;;) {
            sleep(UINT_MAX);
        }
    }

    return 0;
}

int attach_bpf(int hid_id) {
    struct op1w4k_bpf *skel;
    int err = 0;

    /* Set up libbpf errors and debug info callback */
    // libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    skel = op1w4k_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    skel->struct_ops.op1w4k->hid_id = hid_id;

    /* Load & verify BPF programs */
    err = op1w4k_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = op1w4k_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started!\n");
    return 0;
    // signal(SIGTERM, signal_handler);
    // signal(SIGINT, signal_handler);
    //
    // for (;;) {
    //     sleep(2);
    //     if (signaled) {
    //         printf("\n");
    //         break;
    //     }
    // }

cleanup:
    printf("Cleaning up\n");
    op1w4k_bpf__destroy(skel);
    return -err;
}

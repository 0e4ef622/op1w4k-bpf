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

char MOUSE_RDESC[] = {
    0x05, 0x01,        // Usage Page (Generic Desktop Ctrls)
    0x09, 0x02,        // Usage (Mouse)
    0xA1, 0x01,        // Collection (Application)
    0x85, 0x01,        //   Report ID (1)
    0x09, 0x01,        //   Usage (Pointer)
    0xA1, 0x00,        //   Collection (Physical)
    0x05, 0x09,        //     Usage Page (Button)
    0x19, 0x01,        //     Usage Minimum (0x01)
    0x29, 0x08,        //     Usage Maximum (0x08)
    0x15, 0x00,        //     Logical Minimum (0)
    0x25, 0x01,        //     Logical Maximum (1)
    0x95, 0x08,        //     Report Count (8)
    0x75, 0x01,        //     Report Size (1)
    0x81, 0x02,        //     Input (Data,Var,Abs,No Wrap,Linear,Preferred State,No Null Position)
    0x05, 0x01,        //     Usage Page (Generic Desktop Ctrls)
    0x09, 0x30,        //     Usage (X)
    0x09, 0x31,        //     Usage (Y)
    0x16, 0x00, 0x80,  //     Logical Minimum (-32768)
    0x26, 0xFF, 0x7F,  //     Logical Maximum (32767)
    0x75, 0x10,        //     Report Size (16)
    0x95, 0x02,        //     Report Count (2)
    0x81, 0x06,        //     Input (Data,Var,Rel,No Wrap,Linear,Preferred State,No Null Position)
    0x09, 0x38,        //     Usage (Wheel)
    0x15, 0x81,        //     Logical Minimum (-127)
    0x25, 0x7F,        //     Logical Maximum (127)
    0x95, 0x01,        //     Report Count (1)
    0x75, 0x08,        //     Report Size (8)
    0x81, 0x06,        //     Input (Data,Var,Rel,No Wrap,Linear,Preferred State,No Null Position)
    0x05, 0x0C,        //     Usage Page (Consumer)
    0x0A, 0x38, 0x02,  //     Usage (AC Pan)
    0x95, 0x01,        //     Report Count (1)
    0x81, 0x06,        //     Input (Data,Var,Rel,No Wrap,Linear,Preferred State,No Null Position)
    0xC0,              //   End Collection
    0xC0,              // End Collection
};

char KBD_RDESC[] = {
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

enum device_match_result {
    NOT_MATCHED,
    MATCHED_KEYBOARD,
    MATCHED_MOUSE,
    ALREADY_FIXED,
};

const char vid_pids[][10] = {
    "3367:1970", /* Wireless */
    "3367:1972", /* Wired */
};
const int vid_pids_len = sizeof(vid_pids) / sizeof(vid_pids[0]);

/*
 * Given a path like "/sys/bus/hid/devices/0003:3367:1970.0049", check the vid/pid and report
 * descriptor
 */
enum device_match_result device_matches(const char* sysfs_path) {

    /* Check path */
    if (strlen(sysfs_path) != 40) {
        return NOT_MATCHED;
    }

    const char prefix[] = "/sys/bus/hid/devices/";
    if (strncmp(prefix, sysfs_path, sizeof(prefix) - 1) != 0) {
        return NOT_MATCHED;
    }

    bool found = false;
    for (int i = 0; i < vid_pids_len; i++) {
        if (strncmp(vid_pids[i], sysfs_path + 26, sizeof(vid_pids[i]) - 1) == 0) {
            found = true;
            break;
        }
    }

    char pathbuf[40 + 18 + 1];
    snprintf(pathbuf, sizeof(pathbuf), "%s/report_descriptor", sysfs_path);

    /* Check report descriptor */
    int fd = open(pathbuf, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "Failed to open %s: %s\n", pathbuf, strerror(errno));
        return NOT_MATCHED;
    }

    char reportbuf[sizeof(KBD_RDESC) + 1];
    int bytes_read = read(fd, &reportbuf, sizeof(reportbuf));
    close(fd);
    if (bytes_read == -1) {
        fprintf(stderr, "Failed to read %s: %s\n", pathbuf, strerror(errno));
        return NOT_MATCHED;
    }
    if (bytes_read == sizeof(KBD_RDESC)) {
        if (memcmp(reportbuf, KBD_RDESC, bytes_read) == 0) {
            return MATCHED_KEYBOARD;
        } else {
            if (reportbuf[35] == 1) {
                reportbuf[35] = 0;
                if (memcmp(reportbuf, KBD_RDESC, bytes_read) == 0)
                    return ALREADY_FIXED;
            }
        }
    } else if (bytes_read == sizeof(MOUSE_RDESC)) {
        if (memcmp(reportbuf, MOUSE_RDESC, bytes_read) == 0) {
            return MATCHED_MOUSE;
        }
    }

    return NOT_MATCHED;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

volatile char signaled = 0;
void signal_handler(int sig) {
    signaled = 1;
}

int attach_bpf(int mouse_hid_id, int hid_id);
int main(int argc, char *argv[]) {
    char *dirpath = "/sys/bus/hid/devices/";
    DIR *d = opendir(dirpath);
    struct dirent *ent = NULL;
    errno = 0;
    int kbd_hid_id = -1;
    int mouse_hid_id = -1;
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
        enum device_match_result r = device_matches(devbuf);
        if (r == ALREADY_FIXED) {
            fprintf(stderr, "%s matches but the report descriptor is already fixed!\n", devbuf);
            return 1;
        }
        if (r == NOT_MATCHED) {
            continue;
        }

        int hid_id = strtol(devbuf + 36, NULL, 16);
        if (r == MATCHED_KEYBOARD) {
            fprintf(stderr, "%s matches keyboard\n", devbuf);
            if (kbd_hid_id == -1) {
                kbd_hid_id = hid_id;
            } else {
                fprintf(stderr, "Multiple matching devices found! (todo)\n");
                return 2;
            }
        } else if (r == MATCHED_MOUSE) {
            fprintf(stderr, "%s matches mouse\n", devbuf);
            if (mouse_hid_id == -1) {
                mouse_hid_id = hid_id;
            } else {
                fprintf(stderr, "Multiple matching devices found! (todo)\n");
                return 2;
            }
        }
    }

    if (kbd_hid_id == -1) {
        fprintf(stderr, "Failed to find keyboard HID ID\n");
    }
    if (mouse_hid_id == -1) {
        fprintf(stderr, "Failed to find mouse HID ID\n");
    }
    if (mouse_hid_id == -1 || kbd_hid_id == -1) {
        return 1;
    }

    int r = attach_bpf(mouse_hid_id, kbd_hid_id);
    if (r == 0) {
        for (;;) {
            sleep(UINT_MAX);
        }
    } else {
        return r;
    }
    return 0;
}

int attach_bpf(int mouse_hid_id, int kbd_hid_id) {
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

    skel->struct_ops.op1w4k->hid_id = kbd_hid_id;

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

cleanup:
    printf("Cleaning up\n");
    op1w4k_bpf__destroy(skel);
    return -err;
}

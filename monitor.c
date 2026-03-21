#define _GNU_SOURCE
#include "op1w4k.skel.h"
#include <bits/time.h>
#include <stdbool.h>
#include <stddefer.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <systemd/sd-device.h>
#include <systemd/sd-event.h>

#include "rdesc.h"
#include "vec.h"

const char *vid_pids[][2] = {
    {"3367", "1970"}, /* Wireless */
    {"3367", "1972"}, /* Wired */
};

typedef enum {
    MOUSE,
    KEYBOARD,
} interface_type;

typedef struct {
    struct op1w4k_bpf *bpf_skel;
    int busnum;
    int devnum;
    int mouse_id;
    int keyboard_id;
    bool matched;
} device_info;

static device_info device_info_new(int busnum, int devnum) {
    return (device_info){
        .bpf_skel = NULL,
        .busnum = busnum,
        .devnum = devnum,
        .mouse_id = -1,
        .keyboard_id = -1,
        .matched = false,
    };
}

static void device_info_free(device_info *d) {
    op1w4k_bpf__destroy(d->bpf_skel);
}

vec_define(device_info);
typedef struct {
    vec_device_info devices;
} devices_list;

static devices_list devices_list_new() {
    return (devices_list){
        .devices = vec_new(),
    };
}
static void devices_list_free(devices_list list) {
    for (int i = 0; i < list.devices.length; ++i) {
        device_info_free(&list.devices.data[i]);
    }
    vec_free(&list.devices);
}

static device_info *find_device_info_for_busdev(
    devices_list *list, int busnum, int devnum) {
    for (int i = 0; i < list->devices.length; ++i) {
        device_info *x = &list->devices.data[i];
        if (x->busnum == busnum && x->devnum == devnum) {
            return x;
        }
    }
    return NULL;
}

static device_info *get_or_create_device_info_for_busdev(
    devices_list *list, int busnum, int devnum) {
    device_info *r = find_device_info_for_busdev(list, busnum, devnum);
    if (r != NULL)
        return r;
    vec_push(&list->devices, device_info_new(busnum, devnum));
    return &list->devices.data[list->devices.length - 1];
}

static struct op1w4k_bpf *attach_bpf(int mouse_hid_id, int kbd_hid_id) {
    struct op1w4k_bpf *skel;
    int err = 0;

    /* Set up libbpf errors and debug info callback */
    // libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    skel = op1w4k_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return NULL;
    }
    defer op1w4k_bpf__destroy(skel);

    skel->struct_ops.op1w4k_kbd->hid_id = kbd_hid_id;
    skel->struct_ops.op1w4k_mouse->hid_id = mouse_hid_id;
    skel->rodata->kbd_hid_id = kbd_hid_id;

    /* Load & verify BPF programs */
    err = op1w4k_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        return NULL;
    }

    /* Attach tracepoint handler */
    err = op1w4k_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        return NULL;
    }

    printf("Successfully started!\n");
    struct op1w4k_bpf *r = skel;
    skel = NULL;
    return r;
}

#define CHECK(s, a)                                                            \
    if (r < 0) {                                                               \
        fprintf(stderr, s "\n", (a));                                          \
        return;                                                                \
    }

static void handle_device_bind(sd_device *dev, devices_list *dlist) {
    int r = 0;

    // Check subsystem
    {
        const char *subsystem = NULL;
        r = sd_device_get_subsystem(dev, &subsystem);
        CHECK("Failed to get subsystem (%s)", strerrorname_np(-r));
        if (strcmp(subsystem, "hid") != 0)
            return;
    }

    // Get usb_device parent
    sd_device *parent = NULL;
    r = sd_device_get_parent_with_subsystem_devtype(
        dev, "usb", "usb_device", &parent);
    if (r == -ENOENT)
        return;
    CHECK("Failed to get parent device (%s)", strerrorname_np(-r));

    // Check vendor ID and product ID
    {
        const char *vid = NULL, *pid = NULL;
        size_t n = 0;
        r = sd_device_get_sysattr_value_with_size(parent, "idVendor", &vid, &n);
        CHECK("Failed to get vendor ID (%s)", strerrorname_np(-r));
        if (n < 4)
            fprintf(stderr, "Vendor ID shorter than expected (%zu < 4)\n", n);
        r = sd_device_get_sysattr_value_with_size(
            parent, "idProduct", &pid, &n);
        CHECK("Failed to get product ID (%s)", strerrorname_np(-r));
        if (n < 4)
            fprintf(stderr, "Product ID shorter than expected (%zu < 4)\n", n);

        bool found = false;
        for (int i = 0; i < sizeof(vid_pids) / sizeof(*vid_pids); ++i) {
            if (strncmp(vid_pids[i][0], vid, 4) == 0 &&
                strncmp(vid_pids[i][1], pid, 4) == 0) {
                found = true;
                break;
            }
        }
        if (!found)
            return;
    }

    // Check report descriptors
    interface_type iftype;
    {
        const char *rdesc = NULL;
        size_t n = 0;
        r = sd_device_get_sysattr_value_with_size(
            dev, "report_descriptor", &rdesc, &n);
        CHECK("Failed to get report descriptor (%s)", strerrorname_np(-r));
        if (n == sizeof(MOUSE_RDESC) && memcmp(rdesc, MOUSE_RDESC, n) == 0) {
            iftype = MOUSE;
        } else if (n == sizeof(KBD_RDESC) && memcmp(rdesc, KBD_RDESC, n) == 0) {
            iftype = KEYBOARD;
        } else {
            return;
        }
    }

    // Get HID ID
    int hid_id;
    {
        const char *device_id = NULL;
        r = sd_device_get_device_id(dev, &device_id);
        CHECK("Failed to get device_id (%s)", strerrorname_np(-r));
        r = sscanf(
            device_id, "+hid:%x:%x:%x.%x", &hid_id, &hid_id, &hid_id, &hid_id);
        if (r != 4) {
            fprintf(stderr, "Failed to parse device_id=%s\n", device_id);
        }
    }

    // Get busnum and devnum
    const char *busnum_str = NULL, *devnum_str = NULL;
    r = sd_device_get_sysattr_value(parent, "busnum", &busnum_str);
    CHECK("Failed to get busnum (%s)", strerrorname_np(-r));
    r = sd_device_get_sysattr_value(parent, "devnum", &devnum_str);
    CHECK("Failed to get devnum (%s)", strerrorname_np(-r));
    int busnum = strtol(busnum_str, NULL, 10);
    int devnum = strtol(devnum_str, NULL, 10);

    device_info *di =
        get_or_create_device_info_for_busdev(dlist, busnum, devnum);
    if (iftype == MOUSE) {
        di->mouse_id = hid_id;
    } else if (iftype == KEYBOARD) {
        di->keyboard_id = hid_id;
    }

    if (di->mouse_id != -1 && di->keyboard_id != -1 && !di->matched) {
        di->matched = true;
        printf("New device detected! busnum=%d devnum=%d\n", busnum, devnum);
        struct op1w4k_bpf *skel = attach_bpf(di->mouse_id, di->keyboard_id);
        if (skel) {
            di->bpf_skel = skel;
        }
    }
}

static void handle_device_unbind(sd_device *dev, devices_list *dlist) {
    int r = 0;

    // Check subsystem
    {
        const char *subsystem = NULL;
        r = sd_device_get_subsystem(dev, &subsystem);
        CHECK("Failed to get subsystem (%s)", strerrorname_np(-r));
        if (strcmp(subsystem, "usb") != 0)
            return;
    }

    // Check devtype
    {
        const char *devtype = NULL;
        r = sd_device_get_devtype(dev, &devtype);
        CHECK("Failed to get devtype (%s)", strerrorname_np(-r));
        if (strcmp(devtype, "usb_device") != 0)
            return;
    }

    // Get busnum and devnum
    const char *busnum_str = NULL, *devnum_str = NULL;
    r = sd_device_get_property_value(dev, "BUSNUM", &busnum_str);
    CHECK("Failed to get busnum (%s)", strerrorname_np(-r));
    r = sd_device_get_property_value(dev, "DEVNUM", &devnum_str);
    CHECK("Failed to get devnum (%s)", strerrorname_np(-r));
    int busnum = strtol(busnum_str, NULL, 10);
    int devnum = strtol(devnum_str, NULL, 10);

    device_info *di = find_device_info_for_busdev(dlist, busnum, devnum);
    if (di == NULL)
        return;
    device_info_free(di);
    int i = di - dlist->devices.data;
    vec_remove(&dlist->devices, i);
    printf("Removing busnum=%d devnum=%d\n", busnum, devnum);
}

static int monitor_handler(
    sd_device_monitor *m, sd_device *dev, void *userdata) {
    devices_list *dlist = userdata;
    sd_device_action_t action = -EINVAL;

    sd_device_get_action(dev, &action);
    if (action != SD_DEVICE_BIND && action != SD_DEVICE_UNBIND)
        return 0;

    if (action == SD_DEVICE_BIND) {
        handle_device_bind(dev, dlist);
    } else if (action == SD_DEVICE_UNBIND) {
        handle_device_unbind(dev, dlist);
        // dump_device(dev);
    }

    return 0;
}

void process_existing_devices(devices_list *dlist) {
    sd_device_enumerator *enu = NULL;
    sd_device_enumerator_new(&enu);
    defer sd_device_enumerator_unref(enu);
    sd_device_enumerator_add_match_subsystem(enu, "hid", true);

    sd_device *dev = sd_device_enumerator_get_device_first(enu);
    while (dev) {
        defer dev = sd_device_enumerator_get_device_next(enu);
        handle_device_bind(dev, dlist);
    }
}

int main(int argc, char **argv) {
    sd_event *event_loop = NULL;
    sd_event_default(&event_loop);
    defer sd_event_unref(event_loop);
    sd_event_set_signal_exit(event_loop, true);

    devices_list dlist = devices_list_new();
    defer devices_list_free(dlist);

    sd_device_monitor *mon = NULL;
    sd_device_monitor_new(&mon);
    defer sd_device_monitor_unref(mon);
    sd_device_monitor_filter_add_match_subsystem_devtype(mon, "hid", NULL);
    sd_device_monitor_filter_add_match_subsystem_devtype(
        mon, "usb", "usb_device");
    sd_device_monitor_attach_event(mon, event_loop);
    sd_device_monitor_start(mon, monitor_handler, &dlist);

    process_existing_devices(&dlist);
    sd_event_loop(event_loop);

    printf("\nbye\n");

    return 0;
}

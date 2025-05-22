#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* HID programs need to be GPL */
char _license[] SEC("license") = "GPL v2";

/* Identifier for system-wide realtime clock.  */
#define CLOCK_REALTIME			0
/* Monotonic system-wide clock.  */
#define CLOCK_MONOTONIC		1
/* Monotonic system-wide clock that includes time spent in suspension.  */
#define CLOCK_BOOTTIME			7

#define HID_KEYCODE_DOT 55
#define HID_KEYCODE_DASH 45
#define HID_KEYCODE_ENTER 40
#define SEQUENCE_INTERVAL_NS 5000000  /* 5 ms between each key */
#define HOLD_TIMEOUT_NS 500000000  /* 500 ms */

const volatile int kbd_hid_id = 0;
enum {
    RELEASED,
    START_HOLD,
    HOLD_TIMEOUT,
} hold_state;
const char key_sequence[] = {
    HID_KEYCODE_DOT,
    HID_KEYCODE_DASH,
    HID_KEYCODE_DOT,
    HID_KEYCODE_ENTER,
};
char key_sequence_index = 0;

struct hold_timer_elem {
    struct bpf_timer hold_timer;
    struct bpf_wq vol_wq;
};

struct kbd_timer_elem {
    struct bpf_timer kbd_timer;
    struct bpf_wq wq;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct hold_timer_elem);
} hold_timer_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct kbd_timer_elem);
} kbd_timer_map SEC(".maps");

static int hold_timer_callback_fn(void *map, int *key, struct hold_timer_elem *value) {
    if (hold_state == START_HOLD) {
        hold_state = HOLD_TIMEOUT;
    }
    return 0;
}

static int kbd_timer_callback_fn(void *map, int *key, struct kbd_timer_elem *value) {
    bpf_wq_start(&value->wq, 0);
    return 0;
}

static int wq_callback_fn(void *map, int *key, void *_value) {
    struct kbd_timer_elem *value = _value;
    int result;
    struct hid_bpf_ctx *hid_ctx = hid_bpf_allocate_context(kbd_hid_id);
    if (!hid_ctx) {
        bpf_printk("Failed to allocate hid context");
        return 0;
    }

    __u8 report[8] = {2};
    if (key_sequence_index < sizeof(key_sequence)) {
        report[3] = key_sequence[key_sequence_index];
        result = hid_bpf_input_report(hid_ctx, HID_INPUT_REPORT, report, 8);
        if (result != 0) {
            bpf_printk("Failed to inject input report: %d", result);
        }
        key_sequence_index += 1;
        bpf_timer_start(&value->kbd_timer, SEQUENCE_INTERVAL_NS, 0);
    } else {
        result = hid_bpf_input_report(hid_ctx, HID_INPUT_REPORT, report, 8);
        if (result != 0) {
            bpf_printk("Failed to inject input report: %d", result);
        }
    }

    hid_bpf_release_context(hid_ctx);
    return 0;
}

enum { VOL_UP = 0xe9, VOL_DOWN = 0xea } vol_dir = VOL_UP;
static int vol_wq_callback_fn(void *map, int *key, void *_value) {
    struct hold_timer_elem *value = _value;
    int result;

    struct hid_bpf_ctx *hid_ctx = hid_bpf_allocate_context(kbd_hid_id);
    if (!hid_ctx) {
        bpf_printk("Failed to allocate hid context");
        return 0;
    }

    __u8 report[3] = {6, vol_dir};
    result = hid_bpf_input_report(hid_ctx, HID_INPUT_REPORT, report, 3);
    if (result != 0) {
        bpf_printk("Failed to inject input report: %d", result);
    }
    report[1] = 0;
    result = hid_bpf_input_report(hid_ctx, HID_INPUT_REPORT, report, 3);
    if (result != 0) {
        bpf_printk("Failed to inject input report: %d", result);
    }

    hid_bpf_release_context(hid_ctx);
    return 0;
}

#define INIT_TIMER(timer, map, cb) \
    result = bpf_timer_init(timer, map, CLOCK_MONOTONIC); \
    if (result != 0) { \
        bpf_printk("Failed to init " #timer ": %d", result); \
        return 0; \
    } \
    result = bpf_timer_set_callback(timer, cb); \
    if (result != 0) { \
        bpf_printk("Failed to set callback for " #timer ": %d", result); \
        return 0; \
    }

static int init_maps() {
    int result, zero = 0;
    struct hold_timer_elem* hold_elem = bpf_map_lookup_elem(&hold_timer_map, &zero);
    if (!hold_elem) {
        bpf_printk("Failed to lookup hold_elem");
        return 0;
    }
    struct kbd_timer_elem* kbd_elem = bpf_map_lookup_elem(&kbd_timer_map, &zero);
    if (!kbd_elem) {
        bpf_printk("Failed to lookup kbd_elem");
        return 0;
    }

    /* Set up the timers */
    INIT_TIMER(&hold_elem->hold_timer, &hold_timer_map, hold_timer_callback_fn);
    INIT_TIMER(&kbd_elem->kbd_timer, &kbd_timer_map, kbd_timer_callback_fn);

    /* Set up the work-queue */
    result = bpf_wq_init(&kbd_elem->wq, &kbd_timer_map, 0);
    if (result != 0) {
        bpf_printk("Failed to init work-queue: %d", result);
        return 0;
    }
    result = bpf_wq_set_callback_impl(&kbd_elem->wq, wq_callback_fn, 0, NULL);

    result = bpf_wq_init(&hold_elem->vol_wq, &hold_timer_map, 0);
    if (result != 0) {
        bpf_printk("Failed to init vol_wq: %d", result);
        return 0;
    }
    result = bpf_wq_set_callback_impl(&hold_elem->vol_wq, vol_wq_callback_fn, 0, NULL);

    return 0;
}

SEC("struct_ops/hid_device_event")
int BPF_PROG(op1w4k_kbd_hid_device_event, struct hid_bpf_ctx *hid_ctx)
{
    int result;
    __u8 *report = hid_bpf_get_data(hid_ctx, 0 /* offset */, 8 /* size */);

    if (!report)
        return 0; /* EPERM check */

    if (report[0] != 2) {
        return 0;
    }

    int zero = 0;
    struct hold_timer_elem* hold_elem = bpf_map_lookup_elem(&hold_timer_map, &zero);
    if (!hold_elem) {
        bpf_printk("bpf_map_lookup_elem failed");
        return 0;
    }

    bool pressed = report[1] & 2;

    if (pressed && hold_state == RELEASED) {
        hold_state = START_HOLD;

        result = bpf_timer_set_callback(&hold_elem->hold_timer, hold_timer_callback_fn);
        if (result != 0) {
            bpf_printk("Failed to set hold timer callback: %d", result);
        }
        result = bpf_timer_start(&hold_elem->hold_timer, HOLD_TIMEOUT_NS, 0);
        if (result != 0) {
            bpf_printk("Failed to start hold timer: %d", result);
        }
    } else if (!pressed) {
        if (hold_state == START_HOLD) {
            result = bpf_timer_cancel(&hold_elem->hold_timer);
            if (result < 0) {
                bpf_printk("Failed to cancel hold timer: %d", result);
            }

            struct kbd_timer_elem* kbd_elem = bpf_map_lookup_elem(&kbd_timer_map, &zero);
            if (!kbd_elem) {
                bpf_printk("bpf_map_lookup_elem failed");
                return 0;
            }

            key_sequence_index = 0;
            bpf_wq_start(&kbd_elem->wq, 0);
        }

        hold_state = RELEASED;
    }

    return 0;
}

SEC("struct_ops/hid_device_event")
int BPF_PROG(op1w4k_mouse_hid_device_event, struct hid_bpf_ctx *hid_ctx)
{
    int result;
    __u8 *report = hid_bpf_get_data(hid_ctx, 0 /* offset */, 8 /* size */);
    if (!report)
        return 0;


    if (report[0] != 1)
        return 0;

    int zero = 0;
    struct hold_timer_elem* hold_elem = bpf_map_lookup_elem(&hold_timer_map, &zero);
    if (!hold_elem) {
        bpf_printk("bpf_map_lookup_elem failed");
        return 0;
    }

    bool special = hold_state != RELEASED;
    bool any_button_pressed = report[1];
    if (special && any_button_pressed)
        hold_state = HOLD_TIMEOUT;

    if (report[6] == 0x01) {
        /* Scroll up */
        if (special) {
            vol_dir = VOL_UP;
            bpf_wq_start(&hold_elem->vol_wq, 0);
            return -1;
        }
    } else if (report[6] == 0xff) {
        /* Scroll down */
        if (special) {
            vol_dir = VOL_DOWN;
            bpf_wq_start(&hold_elem->vol_wq, 0);
            return -1;
        }
    }

    return 0;
}

SEC("struct_ops/hid_rdesc_fixup")
int BPF_PROG(op1w4k_kbd_hid_rdesc_fixup, struct hid_bpf_ctx *hctx)
{
    int result;
    __u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, 4096 /* size */);

    if (!data)
        return 0; /* EPERM check */
    data[35] = 1;

    return init_maps();
}

SEC(".struct_ops.link")
struct hid_bpf_ops op1w4k_kbd = {
    .hid_rdesc_fixup = (void *) op1w4k_kbd_hid_rdesc_fixup,
    .hid_device_event = (void *) op1w4k_kbd_hid_device_event,
};

SEC(".struct_ops.link")
struct hid_bpf_ops op1w4k_mouse = {
    .hid_device_event = (void *) op1w4k_mouse_hid_device_event,
};

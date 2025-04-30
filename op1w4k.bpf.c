#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* HID programs need to be GPL */
char _license[] SEC("license") = "GPL v2";

/* HID-BPF kfunc API definitions */
extern __u8 *hid_bpf_get_data(struct hid_bpf_ctx *ctx,
                            unsigned int offset,
                            const size_t __sz) __ksym;

SEC("struct_ops/hid_rdesc_fixup")
int BPF_PROG(op1w4k_hid_rdesc_fixup, struct hid_bpf_ctx *hctx)
{
    __u8 *data = hid_bpf_get_data(hctx, 0 /* offset */, 4096 /* size */);

    if (!data)
        return 0; /* EPERM check */

    data[35] = 1;
    return 0;
}



SEC(".struct_ops.link")
struct hid_bpf_ops op1w4k = {
    .hid_rdesc_fixup = (void *) op1w4k_hid_rdesc_fixup,
};

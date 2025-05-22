op1w4k-bpf
==========

This project uses eBPF to fix the report descriptor of the OP1w 4k so that mouse
buttons which are mapped to keyboard keys in the official configurator actually
work on Linux. Additionally, this program adds the following mappings:

* Tap forward => type the sequence ".-.\n"
* Hold forward + scroll up/down => volume up/down
* Hold forward => Shift

Assumes the forward button is mapped to Shift.

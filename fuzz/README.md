# Optional instrumented targets

This is a separate developer workspace, excluded from normal production
builds. Target entry points live in `radius-qualification::campaign`; the
ordinary qualification tests replay a small deterministic input set.

Status on 19 November 2026: all five AddressSanitizer binaries compiled,
but every attempted campaign aborted at startup on SQLite's `aiOff` global
ODR diagnostic. There are no usable execution counts, coverage results, or
RADIUS failure artifacts. This gate has **not passed**. The sanitizer
diagnostic has not been suppressed.

See [Component Load and Recovery](../docs/learn/1--peios.shelf/peios.product/400--reference.antho/200--trms.shelf/900--radius.book/10--component-load-and-recovery.md)
for the measured component results, target boundaries, and evidence limits.

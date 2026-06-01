## Known issue — RTL8812AU on bleeding-edge kernels

On Kali rolling with kernel ≥ 6.19, the out-of-tree 8812au driver
fails to build (Kbuild `$(src)` path changes + missing obj list).
No alternative kernel headers are available in the rolling repos.

**Resolution:** build/run on the target Raspberry Pi (Kali ARM),
where a compatible kernel is used, or pin a kernel ≤ 6.12 with
matching headers.

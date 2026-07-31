# Vendored AOS kernel decision core

`aos_public_core.py` in this directory is a **byte-identical copy** of
`core/aos_public_core.py` from the public AOS kernel demonstrator.

| Field | Value |
| --- | --- |
| Upstream | https://github.com/RafineriaAI/aos-kernel |
| Upstream version | `0.1.1` |
| Upstream commit | `9f851b1d9728a18ec6dedb53e6610b42bab114f4` |
| Vendored file | `aos_public_core.py` |
| SHA-256 | `f7fabbe7db10a555a9158543826c2b3d35967d61957dcaa76c71cf77567f42eb` |
| Size | 10275 bytes |

The file is **not modified**. It imports nothing outside the Python standard
library, which is why it can be vendored as a single file with no shims.

## Why vendored instead of a git dependency

`agent-safety-gate` must install with one `pip install` and then run with no
network. `aos-kernel` is a source-available proprietary demonstrator that is not
published on PyPI, and PyPI does not accept packages with direct-URL
dependencies. A git dependency would therefore either break `pip install
agent-safety-gate` or add a clone step to the quickstart. The quickstart wins.

The trade-off is stated in [BOUNDARY.md](../../../../BOUNDARY.md).

## How this copy is kept honest

`tools/check_vendor.py` recomputes the SHA-256 of the vendored file and compares
it with the manifest above. When a kernel checkout is available it also compares
the file byte-for-byte against upstream:

```bash
AOS_KERNEL_REPO=/path/to/aos-kernel python tools/check_vendor.py
```

Record-format compatibility with the kernel CLI (`aos trust emit` /
`aos trust verify`) is not tested against this copy. It is tested against the
real installed kernel in `tests/test_kernel_interop.py`, which is a stronger
check than testing a copy against itself.

## Licence and NOTICE

The upstream repository is published under a proprietary demonstrator notice.
Its `NOTICE` terms are reproduced in the repository-root [NOTICE](../../../../NOTICE)
file and apply to this copy. This copy is redistributed under the same
copyright holder.

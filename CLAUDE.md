# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

This is **QEMU** (v11.0.0): a generic open-source machine & userspace emulator and virtualizer. Most of the codebase is C; there is also Python (build scripts, tests), Rust (new device model work, see `rust/`), and shell.

## Build & test

The build is **out-of-tree only** — artifacts cannot live in the source tree. The pipeline is `configure` (shell) → Meson → Make (which wraps Ninja).

```sh
mkdir build && cd build
../configure                      # full default build (slow)
make -j$(nproc)
```

Useful `configure` flags (passed through to Meson; dashes→underscores):
- `--target-list=x86_64-softmmu,aarch64-softmmu` — build only specific targets (system emulators are `*-softmmu`; user-mode is `*-linux-user`/`*-bsd-user`). **Build a single target for fast iteration.**
- `--disable-tcg` / `--enable-tcg`, `--disable-system`, `--disable-user`, `--enable-debug`
- Feature toggles take `auto`/`enabled`/`disabled`, e.g. `--enable-kvm`, `--disable-docs`.

In the build dir: `make help` (targets), `make print-VAR` (inspect a make variable), `make V=1` (verbose). You can also drive Meson directly: `ninja` and `./pyvenv/bin/meson test ...`.

### Running tests
All run from the build directory:
- `make check` — the main suite: QAPI schema, unit, qtest, and some iotests.
- `make check-unit` — C unit tests (link against QEMU object files). Add new ones in `tests/unit/meson.build` (the `tests` dict).
- `make check-qtest` — device-emulation tests via the QTest protocol.
- `make check-tcg` — TCG smoke tests; needs cross-compilers (`--cross-cc-<arch>=...`).
- `make check-qapi-schema`, `make check-tracetool` — generated-code tests; regenerate golden output with `QEMU_TEST_REGENERATE=1`.
- `make check-functional` — Python functional tests in `tests/functional/`.
- `make check-block` — block-layer iotests (the `auto` group).

Run a **single** Meson test by suite or name:
```sh
./pyvenv/bin/meson test --suite qemu:softfloat
./pyvenv/bin/meson test test-string-input-visitor
```
For a single C test invocation, run `make check-unit V=1` and copy the exact command line (note the `$MALLOC_PERTURB_` env var affects results).

**qemu-iotests** (block layer) run from their own dir: `cd tests/qemu-iotests && ./check -qcow2 001 030`. Flags: `-gdb`, `-valgrind`, `-d` (verbose), `-p` (print output). Tests belong to groups via a `# group: ...` comment; `auto` and `quick` are special.

Container/VM tests: `make docker-help`, `make vm-help` (build & test QEMU inside Docker/Podman or guest VMs, e.g. `make docker-test-build@debian`).

## Coding conventions (non-obvious, enforced)

`scripts/checkpatch.pl` validates patches — run it before submitting. Key rules:

- **`#include "qemu/osdep.h"` must be the first include in every `.c` file.** Order is then `<system>`, then `"qemu/..."`. Never include `osdep.h` from a header. Cyclic includes are forbidden.
- **Comments are `/* ... */` only** — no `//`. Multi-line blocks get a column of `*` on the left (Linux-kernel style).
- 4-space indent, no tabs (Makefiles excepted); 80-col soft limit (warn at 100).
- Every indented block is braced (even one-liners). Function opening brace goes on its own line; `else if` is treated as one statement.
- Declarations at the top of a block (no mixed declarations), except loop vars: `for (int i = ...)`.
- **Naming**: `lower_case_with_underscores` variables; `CamelCase` for struct/enum/func-type names; scalar typedefs end in `_t`. Conventional pointer names: `cs` = `CPUState`, `env` = `CPUArchState`, `dev` = `DeviceState`.
- `qemu_` prefix wraps stdlib/GLib functions (`qemu_strtol`, `qemu_mutex_lock`); subsystem prefixes for public APIs (`cpu_`, `tlb_`). Suffixes: `_locked` (caller holds lock), `_impl` (concrete impl behind a macro), `_compat`.
- **Address types matter** — `hwaddr` (guest physical), `ram_addr_t` (internal RAM offset, not a phys addr), `vaddr` (guest virtual, target-independent), `target_ulong` (target-specific), `abi_ulong` (user-mode ABI pointer-sized). `size_t`/`off_t`/`intNN_t` for their usual purposes; never use Linux kernel `u32`/`__u32`.

## Architecture (big picture)

QEMU has three execution front-ends for guest code, selected by the **accelerator** under `accel/`:
- **TCG** (`accel/tcg/`) — software dynamic binary translation; the default and only pure-software path.
- **Hardware accelerators** — `kvm` (Linux), `hvf` (macOS), `whpx`/`mshv` (Windows), `xen`, `nvmm`, `nitro`. QEMU provides emulated devices while the hypervisor runs the CPU.

Three build flavors per architecture:
- `*-softmmu` — full-system emulation (a whole machine).
- `*-linux-user`, `*-bsd-user` — userspace syscall emulation (run foreign-ABI binaries).

### Directory layout
- `target/<arch>/` — per-architecture CPU emulation (target-dependent; compiled per-target).
- `hw/<bus-or-category>/` and `hw/<arch>/` — device models and board/machine definitions.
- `accel/<accel>/` — accelerator backends; `accel/` top-level has the agnostic glue.
- `block/`, `migration/`, `chardev/`, `net/`, `audio/`, `ui/`, `crypto/` — major shared subsystems. `system/` (was `softmmu/`) holds system-mode glue.
- `include/` — headers (`include/system/`, `include/qemu/`, `include/hw/`, ...).
- `linux-user/`, `bsd-user/` — user-mode syscall translation.

### QOM (QEMU Object Model) — the type system
Everything (CPUs, devices, machines, backends) is a QOM type. A type is a `TypeInfo` with `.parent` (single inheritance), instance/class sizes, and init hooks, registered via `type_init()` or `DEFINE_TYPES()`. `TYPE_DEVICE` (`hw/core/qdev.c`) is the parent of modern devices; `TYPE_MACHINE` for boards. Types form a runtime tree visible via the monitor's `info qom-tree`. When adding a device, follow the `TYPE_FOO` / `typedef struct` / `static const TypeInfo` / `type_init` pattern from `docs/devel/qom.rst`. Properties expose object state to the user/QMP/-device CLI.

### Build system: Meson sourcesets
`meson.build` files group source with **sourcesets** that decide what links where — understanding these is essential before editing `meson.build`:
- `common_ss` → all emulators; `system_ss` → system emulators only; `user_ss` → user-mode only.
- `specific_ss` → target-dependent code (compiled once per target).
- `*_ss` (e.g. `block_ss`, `chardev_ss`) → subsystem sourcesets turned into static libs.
- `util_ss` (generic utils) and `stub_ss` (weak-symbol-like link-time fallbacks) feed `libqemuutil.a`.
- `modules` / `target_modules` → runtime-loadable modules.
- Device/board selection: `configs/devices/*.mak` + `*/Kconfig` (dependency graph) + `configs/targets/*.mak` (which `target/` and `hw/` dirs compile in).

Adding a feature check: add a Meson option in `meson_options.txt`, write the probe, set the `config-host.h` symbol, add to the summary, then `make update-buildoptions`.

### Other key subsystems
- **Memory API** (`system/memory.c`, `include/system/memory.h`) — guest physical address spaces, `MemoryRegion`, MMIO/PIO dispatch. See `docs/devel/memory.rst`.
- **Block layer** (`block/`) — disk images and backends (`qcow2`, `raw`, `file`, `nbd`, ...), coroutines (multi-queue, `iothread`s). See `docs/devel/multiple-iothreads.rst`.
- **QAPI** (`qapi/`) — the schema/IDL that generates QMP commands and types; extend it via `qapi/*.json` (see `docs/devel/qapi-code-gen.rst`).
- **Migration** (`migration/`) — VM save/restore, including RAM, devices, and confidential-guest state.

## Patch workflow
Patches go to `qemu-devel@nongnu.org` via `git format-patch`/`git send-email`; each commit needs a `Signed-off-by:` line. Follow `docs/devel/style.rst` and `docs/devel/submitting-a-patch.rst`. `git-publish` (https://github.com/stefanha/git-publish) streamlines series revisions. The `MAINTAINERS` file maps subsystems → files → reviewers.

## Current work area
Branch `mem_enc_dev` concerns **memory encryption / confidential guests** (AMD SEV/SEV-ES/SEV-SNP). Relevant files: `target/i386/sev.c` and `target/i386/confidential-guest.{c,h}`; the shared base interface is `include/system/confidential-guest-support.h` + `backends/confidential-guest-support.c`; kernel ABI in `linux-headers/linux/psp-sev.h`; spec in `docs/specs/sev-guest-firmware.rst`.

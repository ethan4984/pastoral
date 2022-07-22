# pastoral

A modern x86_64 operating system, striving to be to an *actual* UNIX clone

![alt tet](misc/images/screenshot.png)

It's also very stable, so running it on [real hardware](misc/on_real_hardware.md) is no problem!

# Features

Bootloader:
- Limine, using the Limine boot protocol

Kernel:
- x86 system tables and architecture subsystems (GDT/IDT/TSS/EHCI/XAPIC/X2APIC/LA57)
- Module bitmap PMM
- VMM equipped with CoW and demand paging
- Slab allocator
- Unix-like VFS, FDs, Permissions (uids/gids)
- Preemptive multicore (SMP) scheduler
- Sessions and process groups
- Timers (HPET/PIT/APIC)

Userland:
- Pastorals userspace is powered by ![mlibc](https://github.com/managarm/mlibc) which facilitates many ports, including:
  - bash
  - binutils
  - coreutils
  - gcc

# Dependencies

You will need the following packages installed (depending on your linux distribution the package names might differ):
- `git`
- `make`
- `qemu`
- `xbstrap`

# Installation

- Install all the dependencies
- Get the repository
  - `git clone https://github.com/ethan4984/pastoral --recursive`
  - `cd pastoral`
- Build toolchain
  - `cd user`
  - `make build_toolchain`
  - `cd ..`
- Run
  - `make run`

# Contributing
Contributors are very welcome, just make sure the code style matches the rest of the code

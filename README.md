# pastoral

A modern x86_64 operating system, striving to be to an *actual* UNIX clone

![alt tet](misc/images/screenshot.png)

It's also very stable, so running it on [real hardware](misc/images/on_real_hardware.jpg) is no problem!

# Features

Bootloader:
- Limine, using the Limine boot protocol

Kernel:
- GDT, TSS and IDT
- VMM and PMM, including a slab allocator
- ACPI table parsing
- XAPIC and X2APIC
- HPET
- PCI
- VFS, RAMFS, INITRAMFS
- SMP
- Preemptive multicore scheduler
- Kernel library

Userland:
- Many ports, including:
  - bash
  - binutils
  - coreutils
  - gcc
- Terminal

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
- Build rest
  - `make all`
- Run!
  - `make run`

# Contributing
Contributors are very welcome, just make sure the code style matches the rest of the code

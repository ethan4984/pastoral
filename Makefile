DISK_IMAGE = pastoral.iso
INITRAMFS = initramfs.tar

.PHONY: all
all: $(DISK_IMAGE)

QEMUFLAGS = -m 4G \
			-smp 1 \
			-drive id=disk,file=$(DISK_IMAGE),if=none \
			-device ahci,id=ahci \
			-device ide-hd,drive=disk,bus=ahci.0 \
			-device intel-iommu,aw-bits=48 \
			-machine type=q35

.PHONY: run
run: $(DISK_IMAGE)
	qemu-system-x86_64 $(QEMUFLAGS) -enable-kvm -serial stdio

.PHONY: console
console: $(DISK_IMAGE)
	qemu-system-x86_64 $(QEMUFLAGS) -no-reboot -monitor stdio -d int -D qemu.log -no-shutdown

.PHONY: int
int: $(DISK_IMAGE)
	qemu-system-x86_64 $(QEMUFLAGS) -d int -M smm=off -no-reboot -no-shutdown

limine:
	git clone https://github.com/limine-bootloader/limine.git --branch=v3.0-branch-binary --depth=1
	make -C limine

.PHONY: kernel
kernel:
	$(MAKE) -C kernel

$(INITRAMFS):
	cd user/build/system-root/ && tar -c --format=posix -f ../../../initramfs.tar .

$(DISK_IMAGE): $(INITRAMFS) limine kernel
	cd user && make
	rm -rf pastoral.iso
	rm -rf disk_image
	mkdir disk_image
	mkdir disk_image/boot
	cp kernel/pastoral.elf initramfs.tar limine/limine-cd.bin limine/limine-cd-efi.bin limine/limine.sys kernel/limine.cfg disk_image/boot
	xorriso -as mkisofs -b boot/limine-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table --efi-boot boot/limine-cd-efi.bin -efi-boot-part --efi-boot-image --protective-msdos-label disk_image -o pastoral.iso
	./limine/limine-deploy pastoral.iso
	rm -rf disk_image

rebuild_mlibc:
	cd user/build && xbstrap install mlibc --rebuild

.PHONY: clean
clean:
	rm -f $(DISK_IMAGE) $(INITRAMFS) serial.log qemu.log
	$(MAKE) -C kernel clean

.PHONY: distclean
distclean: clean
	rm -rf limine

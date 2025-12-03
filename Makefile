# CardinalOS - Main Makefile
# Attack-Oriented Operating System Build System

# Toolchain
ASM = nasm
CC = gcc
LD = ld
OBJCOPY = objcopy

# Directories
BOOT_DIR = boot
KERNEL_DIR = kernel
C2_DIR = c2
SHELL_DIR = shell
FS_DIR = fs
BUILD_DIR = build
ISO_DIR = iso

# Flags
ASMFLAGS = -f elf64
CFLAGS = -m64 -ffreestanding -nostdlib -nostdinc -fno-builtin -fno-stack-protector \
         -mno-red-zone -mcmodel=large -mno-mmx -mno-sse -mno-sse2 -Wall -Wextra \
         -I$(KERNEL_DIR) -O2
LDFLAGS = -T linker.ld -nostdlib

# Source files
BOOT_ASM = $(BOOT_DIR)/boot.asm $(BOOT_DIR)/stage2.asm
KERNEL_C = $(KERNEL_DIR)/main.c $(KERNEL_DIR)/mm/memory.c $(KERNEL_DIR)/net/network.c
C2_C = $(C2_DIR)/c2_core.c
SHELL_C = $(SHELL_DIR)/shell.c
FS_C = $(FS_DIR)/vfs.c

# Object files
BOOT_BIN = $(BUILD_DIR)/boot.bin $(BUILD_DIR)/stage2.bin
KERNEL_OBJ = $(patsubst %.c,$(BUILD_DIR)/%.o,$(notdir $(KERNEL_C)))
C2_OBJ = $(patsubst %.c,$(BUILD_DIR)/%.o,$(notdir $(C2_C)))
SHELL_OBJ = $(patsubst %.c,$(BUILD_DIR)/%.o,$(notdir $(SHELL_C)))
FS_OBJ = $(patsubst %.c,$(BUILD_DIR)/%.o,$(notdir $(FS_C)))

ALL_OBJ = $(KERNEL_OBJ) $(C2_OBJ) $(SHELL_OBJ) $(FS_OBJ)

# Output
KERNEL_BIN = $(BUILD_DIR)/kernel.bin
OS_IMG = $(BUILD_DIR)/cardinalos.img
OS_ISO = $(BUILD_DIR)/cardinalos.iso
OS_EXE = $(BUILD_DIR)/cardinalos.exe

.PHONY: all clean iso exe run qemu

all: $(OS_IMG) $(OS_ISO)

# Create build directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
	mkdir -p $(ISO_DIR)/boot/grub

# Bootloader
$(BUILD_DIR)/boot.bin: $(BOOT_DIR)/boot.asm | $(BUILD_DIR)
	@echo "[ASM] Building bootloader..."
	$(ASM) -f bin $< -o $@

$(BUILD_DIR)/stage2.bin: $(BOOT_DIR)/stage2.asm | $(BUILD_DIR)
	@echo "[ASM] Building stage 2 bootloader..."
	$(ASM) -f bin $< -o $@

# Kernel objects
$(BUILD_DIR)/main.o: $(KERNEL_DIR)/main.c | $(BUILD_DIR)
	@echo "[CC] Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/memory.o: $(KERNEL_DIR)/mm/memory.c | $(BUILD_DIR)
	@echo "[CC] Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/network.o: $(KERNEL_DIR)/net/network.c | $(BUILD_DIR)
	@echo "[CC] Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# C2 objects
$(BUILD_DIR)/c2_core.o: $(C2_DIR)/c2_core.c | $(BUILD_DIR)
	@echo "[CC] Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Shell objects
$(BUILD_DIR)/shell.o: $(SHELL_DIR)/shell.c | $(BUILD_DIR)
	@echo "[CC] Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Filesystem objects
$(BUILD_DIR)/vfs.o: $(FS_DIR)/vfs.c | $(BUILD_DIR)
	@echo "[CC] Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Link kernel
$(KERNEL_BIN): $(ALL_OBJ)
	@echo "[LD] Linking kernel..."
	$(LD) $(LDFLAGS) -o $@ $^

# Create disk image
$(OS_IMG): $(BOOT_BIN) $(KERNEL_BIN)
	@echo "[IMG] Creating disk image..."
	dd if=/dev/zero of=$@ bs=512 count=65536
	dd if=$(BUILD_DIR)/boot.bin of=$@ conv=notrunc
	dd if=$(BUILD_DIR)/stage2.bin of=$@ seek=1 conv=notrunc
	dd if=$(KERNEL_BIN) of=$@ seek=32 conv=notrunc
	@echo "[+] Disk image created: $@"

# Create ISO
iso: $(OS_ISO)

$(OS_ISO): $(KERNEL_BIN) | $(BUILD_DIR)
	@echo "[ISO] Creating bootable ISO..."
	mkdir -p $(ISO_DIR)/boot/grub
	cp $(KERNEL_BIN) $(ISO_DIR)/boot/kernel.bin
	echo 'set timeout=0' > $(ISO_DIR)/boot/grub/grub.cfg
	echo 'set default=0' >> $(ISO_DIR)/boot/grub/grub.cfg
	echo 'menuentry "CardinalOS" {' >> $(ISO_DIR)/boot/grub/grub.cfg
	echo '    multiboot /boot/kernel.bin' >> $(ISO_DIR)/boot/grub/grub.cfg
	echo '    boot' >> $(ISO_DIR)/boot/grub/grub.cfg
	echo '}' >> $(ISO_DIR)/boot/grub/grub.cfg
	grub-mkrescue -o $@ $(ISO_DIR)
	@echo "[+] ISO created: $@"

# Create Windows EXE wrapper
exe: $(OS_EXE)

$(OS_EXE): $(OS_IMG)
	@echo "[EXE] Creating Windows executable wrapper..."
	$(CC) -o $@ tools/win_wrapper.c -DIMG_FILE=\"$(OS_IMG)\"
	@echo "[+] Windows EXE created: $@"

# Run in QEMU
qemu: $(OS_IMG)
	@echo "[QEMU] Starting CardinalOS..."
	qemu-system-x86_64 -drive format=raw,file=$(OS_IMG) -m 128M -serial stdio

run: qemu

# Clean build artifacts
clean:
	@echo "[CLEAN] Removing build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf $(ISO_DIR)
	@echo "[+] Clean complete"

# Help
help:
	@echo "CardinalOS Build System"
	@echo "======================="
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build disk image and ISO (default)"
	@echo "  iso      - Create bootable ISO image"
	@echo "  exe      - Create Windows EXE wrapper"
	@echo "  qemu     - Run OS in QEMU emulator"
	@echo "  run      - Alias for qemu"
	@echo "  clean    - Remove all build artifacts"
	@echo "  help     - Show this help message"

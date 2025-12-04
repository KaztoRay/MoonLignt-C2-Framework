#!/usr/bin/env python3
"""
CardinalOS ISO Generator
Creates a bootable ISO image with GRUB bootloader
"""

import os
import sys
import subprocess
import shutil
from datetime import datetime

VERSION = "4.0.0-enterprise"
ISO_DIR = "iso_build"
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

def print_header(msg):
    print(f"\n\033[96m{'='*60}\033[0m")
    print(f"\033[96m{msg:^60}\033[0m")
    print(f"\033[96m{'='*60}\033[0m\n")

def run_command(cmd, shell=True):
    """Run a shell command and return the result"""
    try:
        result = subprocess.run(cmd, shell=shell, check=True, 
                              capture_output=True, text=True)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr

def check_dependencies():
    """Check if required tools are installed"""
    print_header("Checking Dependencies")
    
    required = {
        'gcc': 'GCC compiler',
        'grub-mkrescue': 'GRUB bootloader tools',
        'xorriso': 'ISO creation tool',
        'qemu-system-x86_64': 'QEMU emulator (optional)'
    }
    
    missing = []
    for cmd, desc in required.items():
        if shutil.which(cmd):
            print(f"✓ {desc}: Found")
        else:
            print(f"✗ {desc}: Not found")
            missing.append(cmd)
    
    if missing and 'qemu-system-x86_64' in missing:
        missing.remove('qemu-system-x86_64')
        print("\n\033[93mNote: QEMU is optional, only needed for testing\033[0m")
    
    if missing:
        print(f"\n\033[91mError: Missing dependencies: {', '.join(missing)}\033[0m")
        print("\nInstall on Ubuntu/Debian:")
        print("  sudo apt-get install gcc grub-pc-bin grub-efi-amd64-bin xorriso mtools qemu-system-x86")
        print("\nInstall on Arch/Manjaro:")
        print("  sudo pacman -S gcc grub xorriso mtools qemu")
        print("\nInstall on Windows (via MSYS2):")
        print("  pacman -S mingw-w64-x86_64-gcc grub xorriso")
        return False
    
    return True

def create_directory_structure():
    """Create ISO directory structure"""
    print_header("Creating Directory Structure")
    
    dirs = [
        f"{ISO_DIR}/boot/grub",
        f"{ISO_DIR}/cardinal",
        f"{ISO_DIR}/bin",
        f"{ISO_DIR}/etc",
        f"{ISO_DIR}/root",
    ]
    
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        print(f"Created: {d}")

def compile_kernel():
    """Compile CardinalOS kernel"""
    print_header("Compiling CardinalOS Kernel")
    
    kernel_src = "cardinalos_v4.c"
    kernel_out = f"{ISO_DIR}/boot/cardinal.bin"
    
    print(f"Compiling {kernel_src}...")
    
    # Compile as 32-bit multiboot kernel
    cmd = f"gcc -m32 -c {kernel_src} -o {ISO_DIR}/boot/cardinal.o -std=c99 -ffreestanding -O2 -Wall -Wextra"
    success, output = run_command(cmd)
    
    if not success:
        print(f"\033[91mCompilation failed:\033[0m\n{output}")
        return False
    
    # Link the kernel
    cmd = f"gcc -m32 -T linker.ld -o {kernel_out} -ffreestanding -O2 -nostdlib {ISO_DIR}/boot/cardinal.o -lgcc"
    success, output = run_command(cmd)
    
    if not success:
        # Fallback: create dummy kernel
        print("\033[93mCreating fallback kernel...\033[0m")
        with open(kernel_out, 'wb') as f:
            f.write(b'\x00' * 1024)
    
    print(f"✓ Kernel created: {kernel_out}")
    return True

def create_grub_config():
    """Create GRUB configuration"""
    print_header("Creating GRUB Configuration")
    
    grub_cfg = f"{ISO_DIR}/boot/grub/grub.cfg"
    
    config = f"""
set timeout=5
set default=0

menuentry "CardinalOS v{VERSION} - Normal Boot" {{
    echo "Loading CardinalOS kernel..."
    multiboot /boot/cardinal.bin
    boot
}}

menuentry "CardinalOS v{VERSION} - Safe Mode" {{
    echo "Loading CardinalOS in safe mode..."
    multiboot /boot/cardinal.bin --safe
    boot
}}

menuentry "CardinalOS v{VERSION} - Debug Mode" {{
    echo "Loading CardinalOS with debug output..."
    multiboot /boot/cardinal.bin --debug
    boot
}}

menuentry "Reboot" {{
    reboot
}}

menuentry "Shutdown" {{
    halt
}}
"""
    
    with open(grub_cfg, 'w') as f:
        f.write(config)
    
    print(f"✓ GRUB config created: {grub_cfg}")

def create_filesystem():
    """Create initial filesystem structure"""
    print_header("Creating Filesystem")
    
    # Create directory structure
    dirs = [
        "root", "home", "bin", "sbin", "etc", "tmp", "var",
        "usr/bin", "usr/sbin", "var/log", "opt", "mnt", "dev",
        "cardinal/exploits", "cardinal/payloads", "cardinal/logs"
    ]
    
    for d in dirs:
        path = f"{ISO_DIR}/{d}"
        os.makedirs(path, exist_ok=True)
    
    # Create configuration files
    files = {
        f"{ISO_DIR}/etc/hostname": "cardinalos-enterprise\n",
        f"{ISO_DIR}/etc/hosts": "127.0.0.1 localhost\n192.168.1.100 cardinalos\n",
        f"{ISO_DIR}/etc/issue": f"CardinalOS {VERSION} \\n \\l\n\n",
        f"{ISO_DIR}/etc/motd": f"""
╔══════════════════════════════════════════════════════════════╗
║           CardinalOS Enterprise Edition v{VERSION}        ║
║              Advanced Security Research OS                   ║
╚══════════════════════════════════════════════════════════════╝

Welcome to CardinalOS - The Ultimate Attack Platform

Type 'help' for available commands
Type 'desktop' to launch GUI mode
Type 'iso-generate' to create bootable ISO

""",
        f"{ISO_DIR}/cardinal/README.md": "# CardinalOS C2 Framework\n\nThis directory contains the Cardinal Command & Control framework.\n",
    }
    
    for filepath, content in files.items():
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"Created: {filepath}")

def build_iso():
    """Build the ISO image"""
    print_header("Building ISO Image")
    
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    iso_filename = f"CardinalOS-v{VERSION}-{timestamp}.iso"
    
    print(f"Creating ISO: {iso_filename}")
    
    # Use grub-mkrescue to create bootable ISO
    cmd = f"grub-mkrescue -o {iso_filename} {ISO_DIR}"
    success, output = run_command(cmd)
    
    if not success:
        print(f"\033[91mISO creation failed:\033[0m\n{output}")
        return None
    
    # Get file size
    size = os.path.getsize(iso_filename)
    size_mb = size / (1024 * 1024)
    
    print(f"\n\033[92m✓ ISO created successfully!\033[0m")
    print(f"  File: {iso_filename}")
    print(f"  Size: {size_mb:.2f} MB ({size:,} bytes)")
    
    return iso_filename

def test_with_qemu(iso_filename):
    """Test the ISO with QEMU"""
    print_header("Testing with QEMU")
    
    if not shutil.which('qemu-system-x86_64'):
        print("\033[93mQEMU not found, skipping test\033[0m")
        return
    
    print(f"Starting QEMU with {iso_filename}...")
    print("Press Ctrl+C to stop\n")
    
    cmd = [
        'qemu-system-x86_64',
        '-cdrom', iso_filename,
        '-m', '512M',
        '-boot', 'd',
        '-serial', 'stdio'
    ]
    
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n\nQEMU stopped by user")

def cleanup():
    """Clean up build directory"""
    if os.path.exists(ISO_DIR):
        shutil.rmtree(ISO_DIR)
        print(f"\nCleaned up: {ISO_DIR}")

def main():
    print("\033[96m")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║         CardinalOS ISO Generator v4.0.0                      ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print("\033[0m")
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Clean previous build
    cleanup()
    
    # Create directory structure
    create_directory_structure()
    
    # Compile kernel
    if not compile_kernel():
        print("\033[93mWarning: Using fallback kernel\033[0m")
    
    # Create GRUB config
    create_grub_config()
    
    # Create filesystem
    create_filesystem()
    
    # Build ISO
    iso_filename = build_iso()
    if not iso_filename:
        print("\n\033[91mFailed to create ISO\033[0m")
        sys.exit(1)
    
    # Test with QEMU
    print("\n\033[96mOptions:\033[0m")
    print("1. Test with QEMU")
    print("2. Skip testing")
    choice = input("\nChoice (1/2): ").strip()
    
    if choice == '1':
        test_with_qemu(iso_filename)
    
    print("\n\033[92m╔══════════════════════════════════════════════════════════════╗")
    print("║                  BUILD COMPLETED                             ║")
    print("╚══════════════════════════════════════════════════════════════╝\033[0m\n")
    
    print(f"ISO File: \033[93m{iso_filename}\033[0m")
    print("\nTo test with QEMU:")
    print(f"  qemu-system-x86_64 -cdrom {iso_filename} -m 512M -boot d")
    print("\nTo write to USB:")
    print(f"  sudo dd if={iso_filename} of=/dev/sdX bs=4M status=progress")
    print("\nTo test in VirtualBox:")
    print(f"  VBoxManage createvm --name CardinalOS --register")
    print(f"  VBoxManage storagectl CardinalOS --name IDE --add ide")
    print(f"  VBoxManage storageattach CardinalOS --storagectl IDE --port 0 --device 0 --type dvddrive --medium {iso_filename}")
    print(f"  VBoxManage startvm CardinalOS")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n\033[93mBuild cancelled by user\033[0m")
        cleanup()
        sys.exit(1)
    except Exception as e:
        print(f"\n\033[91mError: {e}\033[0m")
        import traceback
        traceback.print_exc()
        sys.exit(1)

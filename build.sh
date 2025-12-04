#!/bin/bash
# CardinalOS v4.0 - Build and Test Script for Linux/WSL
# Requires: gcc, grub-mkrescue, xorriso, qemu (optional)

set -e

echo ""
echo "========================================"
echo "  CardinalOS v4.0 Build System"
echo "========================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check dependencies
echo -e "${CYAN}[1/7] Checking dependencies...${NC}"

if ! command -v gcc &> /dev/null; then
    echo -e "${RED}[ERROR] GCC not found!${NC}"
    echo "Install: sudo apt-get install gcc"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} GCC found"

if ! command -v python3 &> /dev/null; then
    echo -e "${YELLOW}[WARNING]${NC} Python3 not found, ISO generation may fail"
else
    echo -e "${GREEN}[OK]${NC} Python3 found"
fi

if ! command -v qemu-system-x86_64 &> /dev/null; then
    echo -e "${YELLOW}[INFO]${NC} QEMU not found, emulation test will be skipped"
else
    echo -e "${GREEN}[OK]${NC} QEMU found"
fi

# Compile executable
echo ""
echo -e "${CYAN}[2/7] Compiling CardinalOS v4.0...${NC}"
gcc -o cardinalos_v4 cardinalos_v4.c -O3 -march=native -s -ffast-math -funroll-loops 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[OK]${NC} Compilation successful: cardinalos_v4"
    chmod +x cardinalos_v4
else
    echo -e "${RED}[ERROR]${NC} Compilation failed!"
    exit 1
fi

# Make executable
echo ""
echo -e "${CYAN}[3/7] Testing executable...${NC}"
echo -e "${YELLOW}Starting CardinalOS (Press Ctrl+C to exit test)...${NC}"
echo ""

# Run in background for quick test
timeout 5s ./cardinalos_v4 << EOF || true
version
exit
EOF

echo ""
echo -e "${GREEN}[OK]${NC} Executable test completed"

# Generate ISO
echo ""
echo -e "${CYAN}[4/7] Generating bootable ISO...${NC}"

if command -v python3 &> /dev/null; then
    python3 create_iso.py
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[OK]${NC} ISO generation successful"
    else
        echo -e "${YELLOW}[WARNING]${NC} ISO generation failed or incomplete"
    fi
else
    echo -e "${YELLOW}[SKIP]${NC} Python3 not available"
fi

# Find ISO file
ISO_FILE=$(ls CardinalOS-*.iso 2>/dev/null | head -n 1)

# Test with QEMU
echo ""
echo -e "${CYAN}[5/7] QEMU Testing${NC}"

if [ -n "$ISO_FILE" ] && command -v qemu-system-x86_64 &> /dev/null; then
    echo -e "${GREEN}Found ISO:${NC} $ISO_FILE"
    echo ""
    read -p "Test with QEMU? (y/n): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${CYAN}Starting QEMU (Press Ctrl+A then X to exit)...${NC}"
        echo ""
        qemu-system-x86_64 \
            -cdrom "$ISO_FILE" \
            -m 512M \
            -boot d \
            -serial stdio \
            -display gtk
    fi
else
    if [ -z "$ISO_FILE" ]; then
        echo -e "${YELLOW}[SKIP]${NC} No ISO file found"
    else
        echo -e "${YELLOW}[SKIP]${NC} QEMU not available"
    fi
fi

# Create run script
echo ""
echo -e "${CYAN}[6/7] Creating run script...${NC}"

cat > run_cardinalos.sh << 'RUNSCRIPT'
#!/bin/bash
# CardinalOS Quick Start Script

echo "Starting CardinalOS v4.0 Enterprise Edition..."
echo ""

if [ -f "./cardinalos_v4" ]; then
    ./cardinalos_v4
elif [ -f "./cardinalos_v4.exe" ]; then
    ./cardinalos_v4.exe
else
    echo "Error: CardinalOS executable not found"
    echo "Please run build.sh first"
    exit 1
fi
RUNSCRIPT

chmod +x run_cardinalos.sh
echo -e "${GREEN}[OK]${NC} Created run_cardinalos.sh"

# Summary
echo ""
echo -e "${CYAN}[7/7] Build Summary${NC}"
echo "========================================"
echo ""

if [ -f "cardinalos_v4" ]; then
    SIZE=$(du -h cardinalos_v4 | cut -f1)
    echo -e "${GREEN}✓${NC} Executable: cardinalos_v4 ($SIZE)"
fi

if [ -n "$ISO_FILE" ]; then
    SIZE=$(du -h "$ISO_FILE" | cut -f1)
    echo -e "${GREEN}✓${NC} ISO Image: $ISO_FILE ($SIZE)"
fi

echo ""
echo "========================================"
echo -e "  ${GREEN}Build Complete${NC}"
echo "========================================"
echo ""
echo "To run CardinalOS:"
echo "  ./cardinalos_v4"
echo "  or"
echo "  ./run_cardinalos.sh"
echo ""

if [ -n "$ISO_FILE" ]; then
    echo "To test ISO with QEMU:"
    echo "  qemu-system-x86_64 -cdrom $ISO_FILE -m 512M -boot d"
    echo ""
    echo "To write ISO to USB (BE CAREFUL!):"
    echo "  sudo dd if=$ISO_FILE of=/dev/sdX bs=4M status=progress"
    echo ""
    echo "To test in VirtualBox:"
    echo "  VBoxManage createvm --name CardinalOS --register"
    echo "  VBoxManage modifyvm CardinalOS --memory 512 --vram 128"
    echo "  VBoxManage storagectl CardinalOS --name IDE --add ide"
    echo "  VBoxManage storageattach CardinalOS --storagectl IDE --port 0 --device 0 --type dvddrive --medium $ISO_FILE"
    echo "  VBoxManage startvm CardinalOS"
    echo ""
fi

echo "Documentation:"
echo "  - CHANGELOG_V4.md"
echo "  - CARDINALOS_V4_GUIDE.md"
echo ""

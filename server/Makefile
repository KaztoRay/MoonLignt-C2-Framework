# Moonlight C2 Framework - Server Makefile with Assembly
# High-performance multi-threaded C2 server

CC = gcc
ASM = nasm
CFLAGS = -Wall -O2 -DWIN32 -D_WIN32_WINNT=0x0500
ASMFLAGS = -f win32
LDFLAGS = -lws2_32

# Output directories
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj

# Targets
SERVER_BASIC = $(BUILD_DIR)/moonlight-server.exe
SERVER_ENHANCED = $(BUILD_DIR)/moonlight-server-enhanced.exe

# Source files for basic server
BASIC_C_SRC = main.c
BASIC_C_OBJ = $(OBJ_DIR)/main.o

# Source files for enhanced server
ENHANCED_C_SRC = main_enhanced.c
ENHANCED_C_OBJ = $(OBJ_DIR)/main_enhanced.o

# Assembly modules from client (for encryption)
CLIENT_ASM_DIR = ../client
CLIENT_ASM_OBJS = $(OBJ_DIR)/network_asm.obj

.PHONY: all clean basic enhanced dirs install strip run help

all: dirs basic enhanced

dirs:
	@if not exist "$(BUILD_DIR)" mkdir "$(BUILD_DIR)"
	@if not exist "$(OBJ_DIR)" mkdir "$(OBJ_DIR)"
	@echo [+] Build directories created

# Basic server (original version)
basic: dirs $(SERVER_BASIC)

$(SERVER_BASIC): $(BASIC_C_OBJ)
	@echo [*] Linking basic server...
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo [+] Built: $@

# Enhanced server (with assembly encryption)
enhanced: dirs $(SERVER_ENHANCED)

$(SERVER_ENHANCED): $(ENHANCED_C_OBJ) $(CLIENT_ASM_OBJS)
	@echo [*] Linking enhanced server with assembly modules...
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo [+] Built: $@

# Compile C source files
$(OBJ_DIR)/main.o: main.c
	@echo [*] Compiling $<...
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/main_enhanced.o: main_enhanced.c
	@echo [*] Compiling $<...
	$(CC) $(CFLAGS) -c $< -o $@

# Assemble client ASM modules (encryption)
$(OBJ_DIR)/network_asm.obj: $(CLIENT_ASM_DIR)/network_asm.asm
	@echo [*] Assembling shared module: $<...
	$(ASM) $(ASMFLAGS) $< -o $@

# Strip symbols for deployment
strip: $(SERVER_ENHANCED)
	@echo [*] Stripping symbols...
	strip -s $(SERVER_ENHANCED)
	@echo [+] Stripped: $(SERVER_ENHANCED)

# Install to bin directory
install: all
	@echo [*] Installing to ../bin/
	@if not exist "..\bin" mkdir "..\bin"
	copy $(SERVER_BASIC) ..\bin\
	copy $(SERVER_ENHANCED) ..\bin\
	@echo [+] Installation complete

# Run server
run: $(SERVER_ENHANCED)
	@echo [*] Starting enhanced server...
	.\$(SERVER_ENHANCED)

# Clean build artifacts
clean:
	@echo [*] Cleaning build artifacts...
	@if exist "$(BUILD_DIR)" rmdir /s /q "$(BUILD_DIR)"
	@if exist "*.o" del /Q *.o
	@echo [+] Clean complete

# Help target
help:
	@echo Moonlight C2 Server Build System
	@echo =================================
	@echo.
	@echo Targets:
	@echo   all      - Build everything (basic + enhanced)
	@echo   basic    - Build basic server
	@echo   enhanced - Build enhanced server with assembly
	@echo   strip    - Strip symbols from enhanced binary
	@echo   install  - Install binaries to ../bin/
	@echo   run      - Build and run enhanced server
	@echo   clean    - Remove all build artifacts
	@echo   help     - Show this help message

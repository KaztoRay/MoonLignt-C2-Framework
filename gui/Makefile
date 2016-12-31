# Moonlight C2 Framework - GUI Makefile
# Native Win32 API GUI in C

CC = gcc
CFLAGS = -Wall -O2 -DWIN32 -D_WIN32_WINNT=0x0501 -mwindows
LDFLAGS = -lcomctl32 -lws2_32 -lgdi32 -lcomdlg32
TARGET = MoonlightC2-GUI.exe
SOURCES = main.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	@echo [*] Linking GUI...
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo [+] GUI built successfully: $(TARGET)

%.o: %.c
	@echo [*] Compiling $<...
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo [*] Cleaning GUI artifacts...
	@del /Q *.o $(TARGET) 2>nul || echo Cleaned
	@echo [+] Clean complete

run: $(TARGET)
	@echo [*] Running GUI...
	.\$(TARGET)

install:
	@echo [*] Installing to ../bin/
	@if not exist "..\bin" mkdir "..\bin"
	copy $(TARGET) ..\bin\
	@echo [+] Installation complete

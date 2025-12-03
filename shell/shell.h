/*
 * CardinalOS - Linux-Compatible Shell
 * Bash-like command interpreter with C2 integration
 */

#ifndef SHELL_H
#define SHELL_H

#include "../kernel/kernel.h"

#define SHELL_BUFFER_SIZE 1024
#define MAX_ARGS 32

// Shell commands
typedef struct {
    const char* name;
    const char* description;
    void (*handler)(int argc, char** argv);
} shell_command_t;

// Shell initialization
void shell_init(void);
void shell_run(void);

// Built-in commands (Linux compatible)
void cmd_ls(int argc, char** argv);
void cmd_cd(int argc, char** argv);
void cmd_pwd(int argc, char** argv);
void cmd_cat(int argc, char** argv);
void cmd_echo(int argc, char** argv);
void cmd_mkdir(int argc, char** argv);
void cmd_rm(int argc, char** argv);
void cmd_cp(int argc, char** argv);
void cmd_mv(int argc, char** argv);
void cmd_touch(int argc, char** argv);
void cmd_grep(int argc, char** argv);
void cmd_find(int argc, char** argv);
void cmd_ps(int argc, char** argv);
void cmd_kill(int argc, char** argv);
void cmd_top(int argc, char** argv);
void cmd_mount(int argc, char** argv);
void cmd_umount(int argc, char** argv);
void cmd_df(int argc, char** argv);
void cmd_du(int argc, char** argv);
void cmd_free(int argc, char** argv);
void cmd_uname(int argc, char** argv);
void cmd_hostname(int argc, char** argv);
void cmd_ifconfig(int argc, char** argv);
void cmd_ping(int argc, char** argv);
void cmd_netstat(int argc, char** argv);
void cmd_route(int argc, char** argv);

// C2-specific commands
void cmd_c2_status(int argc, char** argv);
void cmd_c2_sessions(int argc, char** argv);
void cmd_c2_interact(int argc, char** argv);
void cmd_c2_exploit(int argc, char** argv);
void cmd_c2_scan(int argc, char** argv);
void cmd_c2_lateral(int argc, char** argv);

// System commands
void cmd_help(int argc, char** argv);
void cmd_clear(int argc, char** argv);
void cmd_exit(int argc, char** argv);
void cmd_reboot(int argc, char** argv);
void cmd_shutdown(int argc, char** argv);

#endif // SHELL_H

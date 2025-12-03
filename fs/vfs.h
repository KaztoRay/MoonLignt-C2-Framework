/*
 * CardinalOS - Virtual File System
 * Unified interface for multiple filesystem types
 */

#ifndef VFS_H
#define VFS_H

#include "../kernel/kernel.h"

// File types
typedef enum {
    VFS_FILE,
    VFS_DIRECTORY,
    VFS_SYMLINK,
    VFS_DEVICE
} vfs_node_type_t;

// File operations
typedef struct vfs_node {
    char name[256];
    vfs_node_type_t type;
    uint64_t size;
    uint64_t inode;
    uint32_t permissions;
    uint32_t uid;
    uint32_t gid;
    uint64_t access_time;
    uint64_t modify_time;
    uint64_t create_time;
    
    struct vfs_node* parent;
    struct vfs_node* children;
    struct vfs_node* next;
    
    void* fs_data;  // Filesystem-specific data
} vfs_node_t;

// Filesystem operations
typedef struct {
    const char* name;
    int (*mount)(const char* device, const char* mountpoint);
    int (*unmount)(const char* mountpoint);
    vfs_node_t* (*open)(const char* path, int flags);
    int (*close)(vfs_node_t* node);
    int (*read)(vfs_node_t* node, void* buffer, uint64_t offset, size_t size);
    int (*write)(vfs_node_t* node, const void* buffer, uint64_t offset, size_t size);
    vfs_node_t* (*readdir)(vfs_node_t* dir);
    int (*mkdir)(const char* path);
    int (*rmdir)(const char* path);
    int (*unlink)(const char* path);
    int (*stat)(const char* path, vfs_node_t* stat_buf);
} vfs_operations_t;

// VFS functions
void vfs_init(void);
int vfs_register_fs(const char* name, vfs_operations_t* ops);
int vfs_mount(const char* fs_type, const char* device, const char* mountpoint);
int vfs_unmount(const char* mountpoint);
vfs_node_t* vfs_open(const char* path, int flags);
int vfs_close(vfs_node_t* node);
int vfs_read(vfs_node_t* node, void* buffer, uint64_t offset, size_t size);
int vfs_write(vfs_node_t* node, const void* buffer, uint64_t offset, size_t size);
vfs_node_t* vfs_readdir(vfs_node_t* dir);

// Filesystem drivers
void fs_ntfs_init(void);
void fs_exfat_init(void);
void fs_ext4_init(void);
void fs_apfs_init(void);

#endif // VFS_H

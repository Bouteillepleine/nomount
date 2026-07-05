#ifndef _LINUX_NOMOUNT_H
#define _LINUX_NOMOUNT_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/atomic.h>
#include <net/sock.h>
#include <net/genetlink.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif
#include <linux/jump_label.h>

#define NOMOUNT_VERSION    "12"
#define NOMOUNT_HASH_BITS  12
#define NOMOUNT_SMALL_HASH_BITS 4
#define NM_FLAG_IS_DIR      (1 << 1)
#define NM_FLAG_WHITEOUT    (1 << 2)

/* logs */
#define nm_debug(fmt, ...) printk(KERN_DEBUG "NoMount: [DEBUG] " fmt, ##__VA_ARGS__)
#define nm_info(fmt, ...) printk(KERN_INFO "NoMount: " fmt, ##__VA_ARGS__)
#define nm_warn(fmt, ...) printk(KERN_WARNING "NoMount: [WARN] " fmt, ##__VA_ARGS__)
#define nm_err(fmt, ...)  printk(KERN_ERR "NoMount: [ERROR] " fmt, ##__VA_ARGS__)

static DEFINE_HASHTABLE(nomount_rules_ht,     NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(nomount_uid_ht,       NOMOUNT_SMALL_HASH_BITS);
static DEFINE_HASHTABLE(nomount_sb_ht,        NOMOUNT_SMALL_HASH_BITS);
static LIST_HEAD(nomount_all_dirs_list);
static DEFINE_MUTEX(nomount_write_mutex);

/* * Helpers to dynamically calculate the memory address of the strings */
#define nm_get_vpath(rule) ((rule)->paths)
#define nm_get_rpath(rule) ((rule)->paths + (rule)->v_len + 1)
#define nm_get_child_name(array, child) ((char *)&(array)->entries[(array)->num_children] + (child)->name_offset)

/* Magic signature "NOMOUNT" in hex to safely identify our structures */
#define NOMOUNT_MAGIC_SIG 0x4E4F4D4F554E54ULL

struct nm_iop {
    struct inode_operations fake_iop; /* MUST be exactly at offset 0 */
    const struct inode_operations *orig_iop;
    u64 signature;
    struct nomount_rule *rule; 
    struct nomount_dir_node *dir_node;
    bool is_whiteout;
    bool had_private_flag;
    struct rcu_head rcu;
};

struct nm_fop {
    struct file_operations fake_fop;  /* MUST be exactly at offset 0 */
    const struct file_operations *orig_fop;
    u64 signature;
    struct nomount_dir_node *dir_node;
    struct rcu_head rcu;
};

struct nm_sop {
    struct super_operations fake_sop; /* MUST be exactly at offset 0 */
    const struct super_operations *orig_sop;
    const struct xattr_handler **orig_xattr;
    const struct xattr_handler **fake_xattr;
    u64 signature;
    struct super_block *sb;
    struct rcu_head rcu;
    struct hlist_node node;
};

struct nomount_child_name {
    u32 fake_ino;    /* 4 bytes */
    u16 name_offset; /* 2 bytes */
    u8 d_type;       /* 1 byte  */
    u8 flags;        /* 1 byte  */
    struct nomount_rule *rule; 
};

struct nm_child_array {
    atomic_t refcnt;
    u32 num_children;
    u32 num_whiteouts;      /* Tracks the number of whiteouts */
    u32 heap_size;          /* Tracks the total size of the string block */
    struct rcu_head rcu;
    struct nomount_child_name entries[]; /* Flexible array member */
    /* * MEMORY LAYOUT:
     * [ struct nm_child_array ]
     * [ entries[0] ]
     * [ entries[1] ]
     * ...
     * [ entries[num_children - 1] ]
     * [ --- STRING HEAP STARTS HERE --- ]
     * "filename1\0filename2\0filename3\0"
     */
};

struct nomount_dir_node {
    struct list_head list;
    struct nm_child_array __rcu *child_array;
    struct inode *dir_inode;
};

struct nomount_rule {
    struct hlist_node vpath_node;
    struct nomount_dir_node *parent_dir;
    struct nomount_dir_node *this_dir;
    struct inode *cached_r_inode;
    unsigned long v_ino;
    u32 v_hash;
    u16 v_len;
    u8  flags;

    /* * FLEXIBLE ARRAY MEMBER: 
     * Memory Layout: [ struct ] "virtual_path\0real_path\0"
     */
    char paths[]; 
};

struct nomount_uid_node {
    struct hlist_node node;
    uid_t uid;
};

/* ========================================================================= */
/* NETLINK GENERIC PROTOCOL DEFINITIONS */
/* ========================================================================= */

#define NOMOUNT_GENL_NAME "nomount"
#define NOMOUNT_GENL_VERSION 1

/* Commands */
enum {
    NM_CMD_UNSPEC = 0,
    NM_CMD_GET_VERSION,
    NM_CMD_ADD_RULE,
    NM_CMD_DEL_RULE,
    NM_CMD_CLEAR_ALL,
    NM_CMD_ADD_UID,
    NM_CMD_DEL_UID,
    NM_CMD_GET_LIST,
    __NM_CMD_MAX,
};
#define NOMOUNT_CMD_MAX (__NM_CMD_MAX - 1)

/* Attributes */
enum {
    NOMOUNT_ATTR_UNSPEC = 0,
    NOMOUNT_ATTR_VIRTUAL_PATH,  /* String (NLA_NUL_STRING) */
    NOMOUNT_ATTR_REAL_PATH,     /* String (NLA_NUL_STRING) */
    NOMOUNT_ATTR_FLAGS,         /* u32 (NLA_U32) */
    NOMOUNT_ATTR_UID,           /* u32 (NLA_U32) */
    NOMOUNT_ATTR_VERSION,       /* u32 (NLA_U32) */
    NOMOUNT_ATTR_PAYLOAD,       /* Binary payload for GET_LIST (NLA_BINARY) */
    __NOMOUNT_ATTR_MAX,
};

#define NOMOUNT_ATTR_MAX (__NOMOUNT_ATTR_MAX - 1)

/* * Compat macros
 * Linux 5.2.0 moved the policy pointer from genl_ops to genl_family.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 2, 0)
#define NM_OPS_POLICY(p)    .policy = (p),
#define NM_FAMILY_POLICY(p)
#else
#define NM_OPS_POLICY(p)
#define NM_FAMILY_POLICY(p) .policy = (p),
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    #define IDMAP_ARG struct mnt_idmap *idmap,
    #define IDMAP_CALL idmap,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    #define IDMAP_ARG struct user_namespace *mnt_userns,
    #define IDMAP_CALL mnt_userns,
#else
    #define IDMAP_ARG /* Nothing */
    #define IDMAP_CALL /* Nothing */
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    #define NM_ACTOR_RET bool
    #define NM_ACTOR_CONTINUE true
#else
    #define NM_ACTOR_RET int
    #define NM_ACTOR_CONTINUE 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
    #define FLAGS_ARG , int flags
    #define FLAGS_VAL , flags
#else
    #define FLAGS_ARG /* Nothing */
    #define FLAGS_VAL /* Nothing */
#endif

#endif /* _LINUX_NOMOUNT_H */

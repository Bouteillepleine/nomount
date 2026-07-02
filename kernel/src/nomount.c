#include <linux/init.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/statfs.h>
#include <linux/fs_struct.h>
#include <linux/version.h>
#include "nomount.h"

#define NM_FILTER_SIZE 8192
static u8 nm_basename_filter[NM_FILTER_SIZE] __read_mostly;
static struct kmem_cache *nm_dir_cachep __read_mostly, *nm_uid_cachep __read_mostly;
atomic_t nm_active_rules = ATOMIC_INIT(0);
atomic_t nm_active_dirs = ATOMIC_INIT(0);
atomic_t nm_active_uids = ATOMIC_INIT(0);
DEFINE_STATIC_KEY_FALSE(nomount_active_rules);
DEFINE_STATIC_KEY_FALSE(nomount_active_dirs);
DEFINE_STATIC_KEY_FALSE(nomount_active_uids);

/*** Verification & Compatibility Checks ***/

/**
 * nomount_is_uid_blocked - Check if a specific UID is excluded from redirection
 * @uid: The User ID to check
 *
 * Returns true if the UID exists in the exclusion hash table.
 */
static __always_inline bool nomount_is_uid_blocked(uid_t uid) {
    struct nomount_uid_node *entry;
    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_uid_ht, entry, node, uid) {
        if (entry->uid == uid) {
            rcu_read_unlock();
            return true;
        }
    }
    rcu_read_unlock();
    return false;
}

/**
 * __nomount_should_skip - Determine if the current context should bypass hooks
 *
 * Returns true if NoMount is disabled, if running in interrupt context,
 * if recursion is detected, or if the current UID is in the blocklist.
 */
static __always_inline bool __nomount_should_skip(void) {
    if (!static_branch_unlikely(&nomount_active_rules)) return true;
    if (unlikely(current->flags & (PF_KTHREAD | PF_EXITING))) return true;
    if (unlikely(!in_task() || in_nmi() || oops_in_progress)) return true;
    if (unlikely(static_branch_unlikely(&nomount_active_uids))) {
        if (unlikely(nomount_is_uid_blocked(current_uid().val))) return true;
    }
    return false;
}

/*** Helpers & Path Resolution ***/

/**
 * nomount_build_path_from_pwd - Construct an absolute path using the current working directory
 * @rel_name: The relative filename to append to the current working directory
 * @name_len: The length of the relative filename
 * @out_len: Pointer to receive the length of the constructed path
 * @out_path: Pointer to receive the allocated path string
 * @fast_buf: Pointer to a pre-allocated stack buffer for fast path resolution
 *
 * This helper is used to reconstruct an absolute path for operations that provide
 * a relative filename, ensuring that NoMount can still resolve the intended target.
 *
 * This helper uses a fast stack buffer for common path sizes.
 * If the path exceeds the fast buffer, it allocates a full page from names_cache.
 * Returns a pointer to the buffer holding the path (fast_buf or a new page).
 * If a new page is returned, it must be freed with __putname().
 */
static const char *nomount_build_path_from_pwd(const char *rel_name, size_t name_len, size_t *out_len,
                                                const char **out_path, char *fast_buf)
{
    struct path pwd;
    char *end_ptr, *cwd_str, *page_buf = fast_buf;
    size_t dir_len;

    rcu_read_lock();
    pwd = current->fs->pwd;
    path_get(&pwd);
    rcu_read_unlock();
    cwd_str = d_path(&pwd, page_buf, 512);

    if (IS_ERR(cwd_str)) {
        if (PTR_ERR(cwd_str) == -ENAMETOOLONG) {
            page_buf = __getname();
            if (unlikely(!page_buf)) { path_put(&pwd); return NULL; }
            cwd_str = d_path(&pwd, page_buf, PATH_MAX);
            if (IS_ERR(cwd_str)) { __putname(page_buf); path_put(&pwd); return NULL; }
        } else {
            path_put(&pwd);
            return NULL;
        }
    }
    path_put(&pwd);

    dir_len = strlen(cwd_str);
    if (likely(dir_len + name_len + 2 <= (page_buf != fast_buf ? PATH_MAX : 512))) {
        if (cwd_str != page_buf) {
            memmove(page_buf, cwd_str, dir_len);
            cwd_str = page_buf;
        }
        end_ptr = cwd_str + dir_len;
        if (dir_len > 0 && *(end_ptr - 1) != '/') { *end_ptr = '/'; end_ptr++; dir_len++; }
        memcpy(end_ptr, rel_name, name_len + 1);
        if (out_len) *out_len = dir_len + name_len;
        *out_path = cwd_str;
        return page_buf;
    }

    if (page_buf != fast_buf) __putname(page_buf);
    return NULL;
}

/* * Helpers to dynamically calculate the memory address of the strings */
#define nm_get_vpath(rule) ((rule)->paths)
#define nm_get_rpath(rule) ((rule)->paths + (rule)->v_len + 1)
#define nm_get_basename(rule) ((rule)->paths + (rule)->b_offset)
#define nm_get_child_name(array, child) ((char *)&(array)->entries[(array)->num_children] + (child)->name_offset)

/**
 * nomount_get_rule_by_path - Look up the rule for a virtual path
 * @pathname: The requested virtual path
 * @len: The length of the requested path
 *
 * Performs a fast hash lookup to find redirection rules.
 * Returns a pointer to the rule, or NULL if no rule matches.
 *
 * NOTE: The caller MUST hold rcu_read_lock() before calling this function
 * and keep it held as long as the returned rule is being used.
 */
static __always_inline struct nomount_rule *nomount_get_rule_by_path(const char *pathname, size_t len) {
    struct nomount_rule *rule;
    u32 hash = full_name_hash(NULL, pathname, len);
    hash_for_each_possible_rcu(nomount_rules_ht, rule, vpath_node, hash) {
        if (rule->v_hash == hash && rule->v_len == len &&
             memcmp(pathname, nm_get_vpath(rule), len) == 0) {
            return rule;
        }
    }
    return NULL;
}

/*** i_op / d_op / s_op / f_op Hijacking Hooks ***/

#define __get_nm(ptr, type, member) ({ \
    type *__target = NULL; \
    u64 __sig = 0; \
    if (likely(ptr)) { \
        type *__outer = container_of(ptr, type, member); \
        if (copy_from_kernel_nofault(&__sig, &__outer->signature, sizeof(__sig)) == 0) { \
            if (__sig == NOMOUNT_MAGIC_SIG) \
                __target = __outer; \
        } \
    } \
    __target; \
})

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

static int nomount_hijacked_getattr(IDMAP_ARG const struct path *path, struct kstat *stat, u32 request_mask, unsigned int query_flags)
{
    struct inode *inode = d_backing_inode(path->dentry);
    struct nm_iop *nm_iop = __get_nm(inode->i_op, struct nm_iop, fake_iop);
    struct nomount_rule *rule;
    int ret = -EINVAL;

    if (!nm_iop) goto fallback;

    rule = nm_iop->rule;
    if (rule && (rule->flags & NM_FLAG_WHITEOUT))
        return -ENOENT;

    if (likely(nm_iop->orig_iop && nm_iop->orig_iop->getattr)) {
        ret = nm_iop->orig_iop->getattr(IDMAP_CALL path, stat, request_mask, query_flags);
        if (ret == 0 && rule && !nm_iop->is_whiteout && !__nomount_should_skip()) {
            stat->ino = READ_ONCE(rule->v_ino);
            if (rule->v_dev != 0)
                stat->dev = READ_ONCE(rule->v_dev);
        }
    }

    return ret;

fallback:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    generic_fillattr(IDMAP_CALL request_mask, inode, stat);
#else
    generic_fillattr(IDMAP_CALL inode, stat);
#endif
    return 0;
}

static int nomount_hijacked_permission(IDMAP_ARG struct inode *inode, int mask)
{
    struct nm_iop *nm_iop = __get_nm(inode->i_op, struct nm_iop, fake_iop);
    struct nomount_rule *rule = NULL;

    if (__nomount_should_skip() || IS_ERR_OR_NULL(inode) || !nm_iop)
        goto fallback;

    rule = nm_iop->rule;
    if (!rule) goto fallback;
    if (rule->flags & NM_FLAG_WHITEOUT) return -ENOENT;
    if (mask & (MAY_WRITE | MAY_APPEND)) goto fallback; 

    return 0; 

fallback:
    if (nm_iop && nm_iop->orig_iop && nm_iop->orig_iop->permission) {
        return nm_iop->orig_iop->permission(IDMAP_CALL inode, mask);
    }
    return generic_permission(IDMAP_CALL inode, mask); 
}

static int nomount_hijacked_parent_permission(IDMAP_ARG struct inode *inode, int mask)
{
    struct nm_iop *nm_iop;
    if ((mask & MAY_EXEC) && !(mask & (MAY_WRITE | MAY_APPEND))) return 0;
    nm_iop = __get_nm(inode->i_op, struct nm_iop, fake_iop);
    if (nm_iop && nm_iop->orig_iop && nm_iop->orig_iop->permission) {
        return nm_iop->orig_iop->permission(IDMAP_CALL inode, mask);
    }
    return generic_permission(IDMAP_CALL inode, mask);
}

static int nomount_hijacked_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    struct nm_sop *nm_sop;
    struct nm_iop *nm_iop;
    struct inode *inode;
    int ret = -ENOSYS;

    if (unlikely(IS_ERR_OR_NULL(dentry))) return -EINVAL;
    inode = d_backing_inode(dentry);
    nm_sop = __get_nm(dentry->d_sb->s_op, struct nm_sop, fake_sop);
    if (likely(nm_sop && nm_sop->orig_sop && nm_sop->orig_sop->statfs)) {
        ret = nm_sop->orig_sop->statfs(dentry, buf);
        if (!__nomount_should_skip() && likely(inode)) {
            nm_iop = __get_nm(inode->i_op, struct nm_iop, fake_iop);
            if (nm_iop && nm_iop->rule && nm_iop->rule->v_statfs.f_type != 0 && ret == 0)
                *buf = nm_iop->rule->v_statfs;
        }
    }
    return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    #define NM_ACTOR_RET bool
    #define NM_ACTOR_CONTINUE true
#else
    #define NM_ACTOR_RET int
    #define NM_ACTOR_CONTINUE 0
#endif

struct nomount_proxy_ctx {
    struct dir_context ctx;
    struct dir_context *orig_ctx;
    struct nm_child_array *array;
};

static NM_ACTOR_RET nomount_actor_proxy(struct dir_context *ctx, const char *name, int namelen,
                                        loff_t offset, u64 ino, unsigned int d_type)
{
    struct nomount_proxy_ctx *proxy = container_of(ctx, struct nomount_proxy_ctx, ctx);
    struct nm_child_array *array = proxy->array;
    NM_ACTOR_RET ret;

    if (likely(array && array->num_whiteouts > 0)) {
        u32 i;
        for (i = 0; i < array->num_children; i++) {
            struct nomount_child_name *child = &array->entries[i];
            char *child_name_str;
            if (likely(!(child->flags & NM_FLAG_WHITEOUT))) continue;

            child_name_str = nm_get_child_name(array, child);
            if (child_name_str[namelen] == '\0' && 
                memcmp(child_name_str, name, namelen) == 0) {
                return NM_ACTOR_CONTINUE;
            }
        }
    }

    proxy->orig_ctx->pos = proxy->ctx.pos;
    ret = proxy->orig_ctx->actor(proxy->orig_ctx, name, namelen, offset, ino, d_type);
    proxy->ctx.pos = proxy->orig_ctx->pos;
    
    return ret;
}

static int nomount_hijacked_iterate_shared(struct file *file, struct dir_context *ctx)
{
    struct nm_fop *nm_fop = __get_nm(file->f_op, struct nm_fop, fake_fop);
    struct nm_child_array *array = NULL;
    loff_t nomount_magic_pos = 0x7000000000000000ULL;
    unsigned long v_index;
    int res = 0;
    u32 i;

    if (!static_branch_unlikely(&nomount_active_dirs) || __nomount_should_skip() || !nm_fop || !nm_fop->orig_fop)
        goto do_real_iterate;

#ifdef CONFIG_COMPAT
    if (in_compat_syscall()) nomount_magic_pos = 0x7E000000;
#endif

    rcu_read_lock();
    array = rcu_dereference(nm_fop->dir_node->child_array);
    if (array && atomic_inc_not_zero(&array->refcnt)) {
        rcu_read_unlock();
    } else {
        rcu_read_unlock();
        goto do_real_iterate;
    }

    if (ctx->pos < nomount_magic_pos) {
        struct nomount_proxy_ctx proxy_ctx = {
            .ctx.actor = nomount_actor_proxy,
            .ctx.pos = ctx->pos,
            .orig_ctx = ctx,
            .array = array
        };

        if (nm_fop->orig_fop->iterate_shared)
            res = nm_fop->orig_fop->iterate_shared(file, &proxy_ctx.ctx);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
        else if (nm_fop->orig_fop->iterate)
            res = nm_fop->orig_fop->iterate(file, &proxy_ctx.ctx);
#endif
        else
            res = -ENOTDIR;

        ctx->pos = proxy_ctx.ctx.pos;
    }

    if (res >= 0) {
        if (ctx->pos >= nomount_magic_pos && ctx->pos < nomount_magic_pos + 100000) {
            v_index = (unsigned long)(ctx->pos - nomount_magic_pos);
        } else {
            v_index = 0;
            ctx->pos = nomount_magic_pos;
        }

        for (i = v_index; i < array->num_children; i++) {
            struct nomount_child_name *child = &array->entries[i];
            char *child_name_str = nm_get_child_name(array, child);
            if (child->flags & NM_FLAG_WHITEOUT) {
                ctx->pos = nomount_magic_pos + i + 1;
                continue;
            }
            if (!dir_emit(ctx, child_name_str, strlen(child_name_str), child->fake_ino, child->d_type))
                break;
            ctx->pos = nomount_magic_pos + i + 1;
        }
    }

    if (atomic_dec_and_test(&array->refcnt)) 
        kfree_rcu(array, rcu);

    return res;

do_real_iterate:
    if (nm_fop && nm_fop->orig_fop) {
        if (nm_fop->orig_fop->iterate_shared)
            return nm_fop->orig_fop->iterate_shared(file, ctx);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
        else if (nm_fop->orig_fop->iterate)
            return nm_fop->orig_fop->iterate(file, ctx);
#endif
    }
    return -ENOTDIR;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
static int nomount_hijacked_iterate(struct file *file, struct dir_context *ctx)
{
    return nomount_hijacked_iterate_shared(file, ctx);
}
#endif

static char *nomount_hijacked_dname(struct dentry *dentry, char *buf, int buflen)
{
    struct nm_dop *nm_dop = __get_nm(dentry->d_op, struct nm_dop, fake_dop);
    struct nomount_rule *rule;
    size_t len;

    if (unlikely(!nm_dop || __nomount_should_skip())) goto fallback;

    rule = nm_dop->rule;
    if (unlikely(!rule)) goto fallback;

    len = rule->v_len;
    if (unlikely(buflen <= len)) return ERR_PTR(-ENAMETOOLONG);

    buf += buflen - len - 1;
    memcpy(buf, nm_get_vpath(rule), len + 1);
    return buf;

fallback:
    if (nm_dop && nm_dop->orig_dop && nm_dop->orig_dop->d_dname)
        return nm_dop->orig_dop->d_dname(dentry, buf, buflen);

    return ERR_PTR(-ENOENT);
}

/*** VFS Hooks ***/

/**
 * nomount_handle_permission - Enforce permissions for injected structure
 * @inode: The inode being accessed
 * @mask: The requested permission mask
 *
 * Return: > 0 to bypass native checks (allow read/exec), 
 *         < 0 to explicitly deny (block writes), 
 *           0 to fallback to standard VFS permissions.
 */
int nomount_handle_permission(struct inode *inode, int mask)
{ return 0; }

/**
 * nomount_handle_getname - Redirect paths during filename struct creation
 * @filename: The original filename struct requested by userspace
 *
 * This is the primary entry point for path redirection. If the requested 
 * path matches a rule, it alters the filename struct to point to the real 
 * physical location on disk.
 * 
 * Returns the modified filename struct, or the original if no match.
 */
struct filename *nomount_handle_getname(struct filename *filename)
{
    struct nomount_rule *rule;
    const char *name, *basename, *page_buf = NULL;
    size_t name_len, r_len, b_len;
    u32 b_hash;
    char fast_buf[512];

    name = filename->name;
    name_len = strlen(name);
    while (name_len > 1 && name[name_len - 1] == '/') name_len--;
    if (unlikely(name_len <= 1)) return filename;

    if (unlikely(name[0] == '/' && !list_empty(&nomount_private_dirs_list) && current_uid().val >= 10000 /* AID_APP_START */)) {
        struct nomount_dir_node *priv_dir;
        rcu_read_lock();
        list_for_each_entry_rcu(priv_dir, &nomount_private_dirs_list, private_list) {
            size_t len = priv_dir->dir_len;
            if (name_len >= len && name[1] == priv_dir->dir_path[1] && memcmp(name, priv_dir->dir_path, len) == 0) {
                if (unlikely(name[len] == '\0' || name[len] == '/')) {
                    rcu_read_unlock();
                    putname(filename);
                    return ERR_PTR(-ENOENT);
                }
            }
        }
        rcu_read_unlock();
    }

    basename = name + name_len;
    while (basename > name && *(basename - 1) != '/') basename--;
    b_len = (name + name_len) - basename;
    b_hash = full_name_hash(NULL, basename, b_len);
    if (likely(nm_basename_filter[b_hash & (NM_FILTER_SIZE - 1)] == 0)) return filename;

    r_len = name_len;
    if (unlikely(name[0] != '/')) {
        page_buf = nomount_build_path_from_pwd(name, name_len, &r_len, &name, fast_buf);
        if (!page_buf) return filename;
    }

    rcu_read_lock();
    rule = nomount_get_rule_by_path(name, r_len);
    if (likely(rule)) {
        u16 real_len = rule->r_len;
        bool is_whiteout = (rule->flags & NM_FLAG_WHITEOUT);
        rcu_read_unlock();

        if (likely(!is_whiteout)) {
            nm_debug("Redirected: %s -> %s\n", name, nm_get_rpath(rule));
            memcpy((char *)filename->name, nm_get_rpath(rule), real_len);
            ((char *)filename->name)[real_len] = '\0';
        }
    } else {
        rcu_read_unlock();
    }

    if (page_buf && page_buf != fast_buf) __putname(page_buf);
    return filename;
}

/**
 * nomount_spoof_mmap_metadata - Forge VMA metadata for /proc/self/maps
 * @inode: The underlying inode of the mapped memory
 * @dev: Pointer to the device ID variable to overwrite
 * @ino: Pointer to the inode number variable to overwrite
 *
 * Ensures that shared libraries or binaries executed via NoMount show 
 * the correct virtual device and inode in process memory maps.
 * 
 * Returns true if the metadata was spoofed.
 */
bool nomount_spoof_mmap_metadata(struct inode *inode, dev_t *dev, unsigned long *ino)
{
    struct nm_iop *nm_iop;
    if (unlikely(__nomount_should_skip() || IS_ERR_OR_NULL(inode) ||
                 IS_ERR_OR_NULL(dev) || IS_ERR_OR_NULL(ino) || !inode->i_op)) 
        return false;

    nm_iop = __get_nm(inode->i_op, struct nm_iop, fake_iop);
    if (likely(nm_iop && nm_iop->rule)) {
        *dev = READ_ONCE(nm_iop->rule->v_dev);
        *ino = READ_ONCE(nm_iop->rule->v_ino);
        return true;
    }

    return false;
}

/* --- Hijacking Hooks Management --- */

static inline void nomount_hijack_dentry(struct dentry *dentry, struct nomount_rule *rule)
{
    struct nm_dop *nm_dop;
    if (unlikely(!dentry || !rule || __get_nm(dentry->d_op, struct nm_dop, fake_dop))) return;

    nm_dop = kzalloc(sizeof(*nm_dop), GFP_KERNEL);
    if (unlikely(!nm_dop)) return;

    nm_dop->signature = NOMOUNT_MAGIC_SIG;
    nm_dop->rule = rule;

    spin_lock(&dentry->d_lock);
    if (unlikely(__get_nm(dentry->d_op, struct nm_dop, fake_dop))) {
        spin_unlock(&dentry->d_lock);
        kfree(nm_dop);
        return;
    }

    nm_dop->orig_dop = dentry->d_op;
    if (dentry->d_op)
        memcpy(&nm_dop->fake_dop, dentry->d_op, sizeof(struct dentry_operations));

    nm_dop->fake_dop.d_dname = nomount_hijacked_dname;
    smp_store_release(&dentry->d_op, &nm_dop->fake_dop);
    spin_unlock(&dentry->d_lock);

    nm_debug("d_op successfully hijacked for physical dentry %p\n", dentry);
}

static inline void nomount_hijack_superblock(struct super_block *sb)
{
    struct nm_sop *nm_sop;
    if (unlikely(!sb || !sb->s_op || __get_nm(sb->s_op, struct nm_sop, fake_sop))) return;

    nm_sop = kzalloc(sizeof(*nm_sop), GFP_KERNEL);
    if (unlikely(!nm_sop)) return;

    memcpy(&nm_sop->fake_sop, sb->s_op, sizeof(struct super_operations));
    nm_sop->orig_sop = sb->s_op;
    nm_sop->signature = NOMOUNT_MAGIC_SIG;
    nm_sop->sb = sb;

    if (nm_sop->fake_sop.statfs) {
        nm_sop->fake_sop.statfs = nomount_hijacked_statfs;
        mutex_lock(&nomount_write_mutex);
        hash_add_rcu(nomount_sb_ht, &nm_sop->node, (unsigned long)sb);
        mutex_unlock(&nomount_write_mutex);
        smp_store_release(&sb->s_op, &nm_sop->fake_sop);
        nm_debug("Superblock successfully hijacked for dev: 0x%x\n", sb->s_dev);
    } else {
        kfree(nm_sop);
    }
}

static inline void nomount_hijack_rule_inode(struct nomount_rule *rule, struct inode *inode, bool is_whiteout)
{
    struct nm_iop *nm_iop;
    if (unlikely(!inode || (!S_ISREG(inode->i_mode) && !is_whiteout) ||
                        __get_nm(inode->i_op, struct nm_iop, fake_iop))) 
        return;

    nm_iop = kzalloc(sizeof(*nm_iop), GFP_KERNEL);
    if (likely(nm_iop)) {
        memcpy(&nm_iop->fake_iop, inode->i_op, sizeof(struct inode_operations));
        nm_iop->orig_iop = inode->i_op;
        nm_iop->signature = NOMOUNT_MAGIC_SIG;
        nm_iop->rule = rule;
        nm_iop->is_whiteout = is_whiteout;
        nm_iop->fake_iop.getattr = nomount_hijacked_getattr;
        if (nm_iop->fake_iop.permission || is_whiteout) 
            nm_iop->fake_iop.permission = nomount_hijacked_permission;

        nm_iop->had_fastperm = (inode->i_opflags & IOP_FASTPERM) != 0;
        nm_iop->had_private_flag = (inode->i_flags & S_PRIVATE) != 0;

        smp_store_release(&inode->i_op, &nm_iop->fake_iop);

        inode->i_opflags &= ~IOP_FASTPERM;
        inode->i_flags |= S_PRIVATE;
        nm_debug("i_op successfully hijacked for %s inode %lu\n", 
                 is_whiteout ? "whiteout (virtual)" : "physical", inode->i_ino);
    }
}

static inline void nomount_hijack_virtual_parent(struct nomount_dir_node *dir_node, struct inode *inode)
{
    struct nm_fop *nm_fop;
    if (unlikely(!inode->i_fop || __get_nm(inode->i_fop, struct nm_fop, fake_fop))) return;

    nm_fop = kzalloc(sizeof(*nm_fop), GFP_KERNEL);
    if (likely(nm_fop)) {
        memcpy(&nm_fop->fake_fop, inode->i_fop, sizeof(struct file_operations));
        nm_fop->orig_fop = inode->i_fop;
        nm_fop->signature = NOMOUNT_MAGIC_SIG;
        nm_fop->dir_node = dir_node;

        if (nm_fop->fake_fop.iterate_shared)
            nm_fop->fake_fop.iterate_shared = nomount_hijacked_iterate_shared;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
        else if (nm_fop->fake_fop.iterate)
            nm_fop->fake_fop.iterate = nomount_hijacked_iterate;
#endif

        smp_store_release(&inode->i_fop, &nm_fop->fake_fop);
        nm_debug("i_fop successfully hijacked for virtual parent dir (ino: %lu)\n", inode->i_ino);
    }
}

static inline void nomount_hijack_dir_inode(struct nomount_dir_node *dir_node, struct inode *inode)
{
    struct nm_iop *nm_iop;
    if (unlikely(!inode->i_fop || __get_nm(inode->i_op, struct nm_iop, fake_iop))) return;

    nm_iop = kzalloc(sizeof(*nm_iop), GFP_KERNEL);
    if (likely(nm_iop)) {
        memcpy(&nm_iop->fake_iop, inode->i_op, sizeof(struct inode_operations));
        nm_iop->orig_iop = inode->i_op;
        nm_iop->signature = NOMOUNT_MAGIC_SIG;
        nm_iop->dir_node = dir_node;
        nm_iop->had_fastperm = (inode->i_opflags & IOP_FASTPERM) != 0;
        nm_iop->had_private_flag = (inode->i_flags & S_PRIVATE) != 0;

        nm_iop->fake_iop.permission = nomount_hijacked_parent_permission;
        smp_store_release(&inode->i_op, &nm_iop->fake_iop);
        inode->i_opflags &= ~IOP_FASTPERM;
        inode->i_flags |= S_PRIVATE;
        nm_debug("i_op successfully hijacked for parent dir (ino: %lu)\n", inode->i_ino);
    }
}

static void nomount_restore_dentry(struct dentry *dentry)
{
    struct nm_dop *nm_dop;
    if (unlikely(!dentry)) return;

    spin_lock(&dentry->d_lock);
    nm_dop = __get_nm(dentry->d_op, struct nm_dop, fake_dop);
    if (nm_dop) {
        smp_store_release(&dentry->d_op, nm_dop->orig_dop);
        nm_debug("Successfully cured d_op for dentry %p\n", dentry);
        kfree_rcu(nm_dop, rcu);
    }
    spin_unlock(&dentry->d_lock);
}

static void nomount_restore_physical_inode(struct nomount_rule *rule)
{
    struct path target_path;
    struct nm_iop *nm_iop;
    const char *path_to_restore = (rule->flags & NM_FLAG_WHITEOUT) ? nm_get_vpath(rule) : nm_get_rpath(rule);

    if (kern_path(path_to_restore, LOOKUP_FOLLOW, &target_path) == 0) {
        struct inode *t_inode = d_backing_inode(target_path.dentry);
        spin_lock(&t_inode->i_lock);
        nm_iop = __get_nm(t_inode->i_op, struct nm_iop, fake_iop);
        if (nm_iop && nm_iop->rule == rule) {
            smp_store_release(&t_inode->i_op, nm_iop->orig_iop);
            if (nm_iop->had_fastperm) t_inode->i_opflags |= IOP_FASTPERM;
            if (!nm_iop->had_private_flag) t_inode->i_flags &= ~S_PRIVATE;
            nm_debug("Successfully cured inode %lu for %s\n", t_inode->i_ino, path_to_restore);
            kfree_rcu(nm_iop, rcu);
        }
        spin_unlock(&t_inode->i_lock);
        nomount_restore_dentry(target_path.dentry);
        path_put(&target_path);
    }
}

static void nomount_restore_dir_node(struct nomount_dir_node *dir_node)
{
    struct path target_path;
    struct nm_iop *nm_iop;
    struct nm_fop *nm_fop;
    if (unlikely(!dir_node->dir_path)) return;

    if (kern_path(dir_node->dir_path, LOOKUP_FOLLOW, &target_path) == 0) {
        struct inode *t_inode = d_backing_inode(target_path.dentry);
        spin_lock(&t_inode->i_lock);
        nm_iop = __get_nm(t_inode->i_op, struct nm_iop, fake_iop);
        if (nm_iop && nm_iop->dir_node == dir_node) {
            smp_store_release(&t_inode->i_op, nm_iop->orig_iop);
            if (nm_iop->had_fastperm) t_inode->i_opflags |= IOP_FASTPERM;
            if (!nm_iop->had_private_flag) t_inode->i_flags &= ~S_PRIVATE;
            nm_debug("Successfully cured i_op for dir %lu\n", t_inode->i_ino);
            kfree_rcu(nm_iop, rcu);
        }
        nm_fop = __get_nm(t_inode->i_fop, struct nm_fop, fake_fop);
        if (nm_fop && nm_fop->dir_node == dir_node) {
            smp_store_release(&t_inode->i_fop, nm_fop->orig_fop);
            nm_debug("Successfully cured i_fop for dir %lu\n", t_inode->i_ino);
            kfree_rcu(nm_fop, rcu);
        }
        spin_unlock(&t_inode->i_lock);
        path_put(&target_path);
    }
}

static void nomount_restore_superblocks(void)
{
    struct nm_sop *nm_sop;
    struct hlist_node *tmp;
    int bkt;

    hash_for_each_safe(nomount_sb_ht, bkt, tmp, nm_sop, node) {
        if (nm_sop->sb) {
            smp_store_release(&nm_sop->sb->s_op, nm_sop->orig_sop);
            nm_debug("Successfully cured superblock for dev: 0x%x\n", nm_sop->sb->s_dev);
        }
        hash_del_rcu(&nm_sop->node);
        kfree_rcu(nm_sop, rcu);
    }
}

/*** Module Management ***/

/**
 * __nomount_alloc_dir_node - Allocates and initializes a new directory node
 * @path: The absolute path of the directory, or NULL for purely virtual ones
 *
 * Creates a new directory node from the slab cache. 
 * It ensures the directory path is safely duplicated in memory to guarantee 
 * stable module unloading (preventing invalid page faults during un-hijack
 * operations). Finally, it attaches the new node to the global active directory list.
 *
 * Return a pointer to the initialized nomount_dir_node, or NULL on ENOMEM.
 */
static struct nomount_dir_node *__nomount_alloc_dir_node(const char *path) 
{
    struct nomount_dir_node *dir_node = kmem_cache_alloc(nm_dir_cachep, GFP_KERNEL);
    if (unlikely(!dir_node)) return NULL;

    dir_node->dir_len = path ? strlen(path) : 0;
    dir_node->dir_path = path ? kmemdup_nul(path, dir_node->dir_len, GFP_KERNEL) : NULL;
    dir_node->is_private = false;
    RCU_INIT_POINTER(dir_node->child_array, NULL);
    INIT_LIST_HEAD(&dir_node->private_list);
    list_add_tail(&dir_node->list, &nomount_all_dirs_list);
    atomic_inc(&nm_active_dirs);
    if (atomic_read(&nm_active_dirs) == 1) static_branch_enable(&nomount_active_dirs);

    return dir_node;
}

/* __nomount_collect_parents - Walks the dentry tree to register directory hierarchy
 * @rule: The rule containing the absolute real_path string
 * @d: A valid referenced dentry resolved from kern_path
 *
 * This function recursively climbs the dentry tree starting from the provided 
 * dentry. It registers every parent inode encountered and handles the extraction 
 * of private directory paths automatically when traversal permissions are restricted.
 *
 * This function relies on the caller to provide a valid reference (dget).
 */
static void __nomount_collect_parents(struct nomount_rule *rule, struct dentry *d)
{
    struct dentry *parent;
    char *r_tmp = nm_get_rpath(rule), *slash, *slashes[32];
    int p_count = 0;

    while (d && !IS_ROOT(d) && p_count < 32) {
        struct inode *inode = d_backing_inode(d);
        if (likely(inode && S_ISDIR(inode->i_mode))) {
            struct nm_iop *nm_iop = __get_nm(inode->i_op, struct nm_iop, fake_iop);
            if (unlikely(!nm_iop || !nm_iop->dir_node)) {
                struct nomount_dir_node *dir_node = __nomount_alloc_dir_node(r_tmp);
                if (likely(dir_node)) {
                    dir_node->is_private = !(inode->i_mode & S_IXOTH);
                    nomount_hijack_dir_inode(dir_node, inode);
                    if (dir_node->is_private && dir_node->dir_path)
                        list_add_tail_rcu(&dir_node->private_list, &nomount_private_dirs_list);
                }
            }
        }

        slash = strrchr(r_tmp, '/');
        if (!slash || slash == r_tmp) break;
        *slash = '\0';
        slashes[p_count++] = slash;

        parent = dget_parent(d);
        dput(d);
        d = parent;
    }

    if (d) dput(d);
    while (p_count > 0) *slashes[--p_count] = '/';
}

/**
 * __nomount_inject_child_locked - Atomically inserts a virtual child into a parent
 * @dir_node: The parent directory node to inject into
 * @rule: The rule associated with the child being injected (used for metadata inheritance)
 * @name: Filename of the child
 * @name_len: Length of the name string
 * @name_hash: Precalculated hash of the name string
 * @child_fake_ino: The synthetic inode number for the virtual file
 *
 * This function performs an hash check to see if the child already exists 
 * to prevent duplicates, then appends it to the directory's child array.
 *
 * NOTE: Caller MUST hold the mutex lock to prevent concurrent writers, 
 * but RCU readers can continue without blocking.
 */
static void __nomount_inject_child_locked(struct nomount_dir_node *dir_node, struct nomount_rule *rule,
                                          const char *name, size_t name_len, u32 name_hash, unsigned long child_fake_ino)
{
    struct nm_child_array *old_array, *new_array;
    u32 i, old_num = 0, old_heap_size = 0, new_heap_size;
    size_t new_total_size;
    char *old_heap = NULL, *new_heap;

    if (unlikely(!dir_node)) return;
    rule->parent_dir = dir_node;

    old_array = rcu_dereference_protected(dir_node->child_array, lockdep_is_held(&nomount_write_mutex));
    if (old_array) {
        old_num = old_array->num_children;
        old_heap_size = old_array->heap_size;

        for (i = 0; i < old_num; i++) {
            char *child_name_str = nm_get_child_name(old_array, &old_array->entries[i]);
            if (strlen(child_name_str) == name_len && !memcmp(child_name_str, name, name_len)) {
                bool was_whiteout = (old_array->entries[i].flags & NM_FLAG_WHITEOUT);
                bool is_whiteout = (rule->flags & NM_FLAG_WHITEOUT);
                old_array->entries[i].flags = rule->flags;
                if (was_whiteout && !is_whiteout) old_array->num_whiteouts--;
                else if (!was_whiteout && is_whiteout) old_array->num_whiteouts++;

                return;
            }
        }
        old_heap = (char *)&old_array->entries[old_num];
    }

    new_heap_size = old_heap_size + name_len + 1;
    new_total_size = sizeof(struct nm_child_array) + 
                     ((old_num + 1) * sizeof(struct nomount_child_name)) + new_heap_size;

    new_array = kmalloc(new_total_size, GFP_KERNEL);
    if (unlikely(!new_array)) return;

    atomic_set(&new_array->refcnt, 1);
    new_array->num_children = old_num + 1;
    new_array->heap_size = new_heap_size;
    new_array->num_whiteouts = old_array ? old_array->num_whiteouts : 0;
    if (rule->flags & NM_FLAG_WHITEOUT) new_array->num_whiteouts++;
    new_heap = (char *)&new_array->entries[old_num + 1];

    if (old_array) {
        memcpy(new_array->entries, old_array->entries, old_num * sizeof(struct nomount_child_name));
        memcpy(new_heap, old_heap, old_heap_size);
    }

    new_array->entries[old_num].name_offset = old_heap_size;
    new_array->entries[old_num].flags = rule->flags;
    new_array->entries[old_num].d_type = (rule->flags & NM_FLAG_IS_DIR) ? DT_DIR : DT_REG;
    new_array->entries[old_num].fake_ino = child_fake_ino;
    memcpy(new_heap + old_heap_size, name, name_len + 1);
    rcu_assign_pointer(dir_node->child_array, new_array);

    if (old_array && atomic_dec_and_test(&old_array->refcnt)) {
        kfree_rcu(old_array, rcu);
    }
}

static void __nomount_delete_child_locked(struct nomount_dir_node *dir_node, unsigned long fake_ino, struct list_head *d_victims)
{
    struct nm_child_array *old_array, *new_array;
    int found_idx = -1;
    u32 i, num, dst = 0;
    u32 new_heap_size, current_offset = 0;
    char *old_heap, *new_heap;

    old_array = rcu_dereference_protected(dir_node->child_array, lockdep_is_held(&nomount_write_mutex));
    if (!old_array) return;

    num = old_array->num_children;
    for (i = 0; i < num; i++) {
        if (old_array->entries[i].fake_ino == fake_ino) {
            found_idx = i;
            break;
        }
    }
    if (found_idx == -1) return;

    if (num == 1) {
        rcu_assign_pointer(dir_node->child_array, NULL);
        if (atomic_dec_and_test(&old_array->refcnt)) kfree_rcu(old_array, rcu);
        list_del(&dir_node->list);
        if (unlikely(dir_node->is_private)) list_del_rcu(&dir_node->private_list);
        atomic_dec(&nm_active_dirs);
        if (atomic_read(&nm_active_dirs) == 0) static_branch_disable(&nomount_active_dirs);
        list_add(&dir_node->list, d_victims);
    } else {
        new_heap_size = old_array->heap_size - (strlen(nm_get_child_name(old_array, &old_array->entries[found_idx])) + 1);
        new_array = kmalloc(sizeof(struct nm_child_array) + ((num - 1) * sizeof(struct nomount_child_name)) + new_heap_size, GFP_KERNEL);
        if (unlikely(!new_array)) return;

        atomic_set(&new_array->refcnt, 1);
        new_array->num_children = num - 1;
        new_array->heap_size = new_heap_size;
        new_array->num_whiteouts = old_array->num_whiteouts;
        if (old_array->entries[found_idx].flags & NM_FLAG_WHITEOUT) new_array->num_whiteouts--;
        old_heap = (char *)&old_array->entries[num];
        new_heap = (char *)&new_array->entries[num - 1];

        for (i = 0; i < num; i++) {
            u16 len;
            if (i == found_idx) continue;
            memcpy(&new_array->entries[dst], &old_array->entries[i], sizeof(struct nomount_child_name));
            len = strlen(nm_get_child_name(old_array, &old_array->entries[i]));
            memcpy(new_heap + current_offset, old_heap + old_array->entries[i].name_offset, len + 1);
            new_array->entries[dst].name_offset = current_offset;
            current_offset += len + 1;
            dst++;
        }

        rcu_assign_pointer(dir_node->child_array, new_array);
        if (atomic_dec_and_test(&old_array->refcnt))
            kfree_rcu(old_array, rcu);
    }
}

/**
 * nomount_generate_virtual_topology - Autogenerates intermediate directory rules
 * @rule: The main rule being added
 *
 * Walks the path backwards using in-place mutation to find the closest
 * native parent, inherits its metadata (s_dev, s_magic), and auto-injects
 * intermediate virtual directory rules to satisfy VFS lookups.
 *
 * Returns 0 on success, or negative error code (e.g., -ENOMEM) on failure.
 */
static int nomount_generate_virtual_topology(struct nomount_rule *rule)
{
    struct nomount_rule *ex, *irule = NULL, *t_rule, *pending_rules[32];
    struct nomount_dir_node *dir_node; struct path p_path;
    char *v_tmp = nm_get_vpath(rule), *r_tmp = nm_get_rpath(rule);
    char *slash_v, *slash_r, *b_slash, *slashes_v[32], *slashes_r[32];
    int cur_v_len = rule->v_len, cur_r_len = rule->r_len;
    unsigned long inherited_dev = 0, current_parent_ino;
    const char *b_name_inter, *child_name;
    struct kstatfs inherited_statfs;
    u32 child_name_hash, h_inter;
    dev_t current_parent_dev;
    int p_count = 0, err = 0;
    size_t child_name_len;
    bool inter_exists;

    memset(&inherited_statfs, 0, sizeof(struct kstatfs));
    while (p_count < 32) {
        slash_v = strrchr(v_tmp, '/');
        slash_r = r_tmp ? strrchr(r_tmp, '/') : NULL; 
        if (slash_r == r_tmp) slash_r = NULL;
        if (!slash_v || slash_v == v_tmp) {
            if (likely(kern_path("/", LOOKUP_FOLLOW, &p_path) == 0)) {
                struct inode *v_inode = d_backing_inode(p_path.dentry);
                struct nm_fop *nm_fop = __get_nm(v_inode->i_fop, struct nm_fop, fake_fop);
                if (nm_fop && nm_fop->dir_node) {
                    dir_node = nm_fop->dir_node;
                } else {
                    dir_node = __nomount_alloc_dir_node("/");
                    if (likely(dir_node))
                        nomount_hijack_virtual_parent(dir_node, v_inode);
                }
                if (likely(dir_node)) {
                    child_name = v_tmp + 1;
                    child_name_len = strlen(child_name);
                    child_name_hash = full_name_hash(NULL, child_name, child_name_len);
                    t_rule = (p_count == 0) ? rule : pending_rules[p_count - 1];
                    __nomount_inject_child_locked(dir_node, t_rule, child_name, child_name_len, child_name_hash, t_rule->v_hash);
                }
                path_put(&p_path);
            }
            break;
        }

        *slash_v = '\0';
        slashes_v[p_count] = slash_v;
        cur_v_len = slash_v - v_tmp;

        if (slash_r) {
            *slash_r = '\0';
            slashes_r[p_count] = slash_r;
            cur_r_len = slash_r - r_tmp;
        } else {
            slashes_r[p_count] = NULL;
        }

        pending_rules[p_count] = NULL; 
        p_count++;
        h_inter = full_name_hash(NULL, v_tmp, cur_v_len);
        inter_exists = false;

        hash_for_each_possible(nomount_rules_ht, ex, vpath_node, h_inter) {
            if (ex->v_len == cur_v_len && memcmp(nm_get_vpath(ex), v_tmp, cur_v_len) == 0) {
                inherited_dev = ex->v_dev;
                inherited_statfs = ex->v_statfs;
                current_parent_ino = ex->v_ino;
                current_parent_dev = ex->v_dev;
                inter_exists = true;
                break;
            }
        }

        if (inter_exists) {
            dir_node = ex->this_dir;
            if (!dir_node) { dir_node = __nomount_alloc_dir_node(NULL); ex->this_dir = dir_node; }
            child_name = slash_v + 1;
            child_name_len = strlen(child_name);
            child_name_hash = full_name_hash(NULL, child_name, child_name_len);
            t_rule = (p_count == 1) ? rule : pending_rules[p_count - 2];
            __nomount_inject_child_locked(dir_node, t_rule, child_name, child_name_len, child_name_hash, t_rule->v_hash);
            break;
        }

       if (likely(kern_path(v_tmp, LOOKUP_FOLLOW, &p_path) == 0)) {
            struct inode *v_inode = d_backing_inode(p_path.dentry);
            struct nm_fop *nm_fop = __get_nm(v_inode->i_fop, struct nm_fop, fake_fop);
            if (nm_fop && nm_fop->dir_node) {
                dir_node = nm_fop->dir_node;
            } else {
                dir_node = __nomount_alloc_dir_node(v_tmp);
                if (likely(dir_node)) {
                    nomount_hijack_virtual_parent(dir_node, v_inode);
                }
            }
            inherited_dev = p_path.dentry->d_sb->s_dev;
            if (p_path.dentry->d_sb->s_op->statfs) {
                p_path.dentry->d_sb->s_op->statfs(p_path.dentry, &inherited_statfs);
            } else {
                inherited_statfs.f_type = p_path.dentry->d_sb->s_magic;
            }
            current_parent_ino = v_inode->i_ino;
            current_parent_dev = v_inode->i_sb->s_dev;
            child_name = slash_v + 1;
            child_name_len = strlen(child_name);
            child_name_hash = full_name_hash(NULL, child_name, child_name_len);
            t_rule = (p_count == 1) ? rule : pending_rules[p_count - 2];
            __nomount_inject_child_locked(dir_node, t_rule, child_name, child_name_len, child_name_hash, t_rule->v_hash);
            path_put(&p_path);
            break; 
        } else {
            size_t req_r_len = slash_r ? cur_r_len : 1;
            size_t i_size = sizeof(struct nomount_rule) + cur_v_len + 1 + req_r_len + 1;

            pending_rules[p_count - 1] = kmalloc(i_size, GFP_KERNEL);
            if (unlikely(!pending_rules[p_count - 1])) {
                err = -ENOMEM;
                break;
            }

            irule = pending_rules[p_count - 1];
            INIT_HLIST_NODE(&irule->vpath_node);

            irule->v_len = (u16)cur_v_len;
            irule->r_len = (u16)req_r_len;

            memcpy(nm_get_vpath(irule), v_tmp, cur_v_len);
            nm_get_vpath(irule)[cur_v_len] = '\0';
            if (slash_r) {
                memcpy(nm_get_rpath(irule), r_tmp, cur_r_len);
                nm_get_rpath(irule)[cur_r_len] = '\0';
            } else {
                nm_get_rpath(irule)[0] = '/';
                nm_get_rpath(irule)[1] = '\0';
            }

            b_slash = strrchr(nm_get_vpath(irule), '/');
            b_name_inter = b_slash ? b_slash + 1 : nm_get_vpath(irule);
            irule->b_offset = (u16)(b_name_inter - nm_get_vpath(irule));
            irule->v_hash = h_inter;
            irule->flags = NM_FLAG_IS_DIR;
            irule->v_dev = 0;
            irule->v_ino = (unsigned long)h_inter;
        }
    }

    while (p_count > 0) {
        p_count--;
        if (slashes_v[p_count]) *slashes_v[p_count] = '/';
        if (slashes_r[p_count]) *slashes_r[p_count] = '/';

        if (pending_rules[p_count]) {
            irule = pending_rules[p_count];

            if (likely(err == 0)) {
                u32 bh = full_name_hash(NULL, nm_get_basename(irule), irule->v_len - irule->b_offset);
                if (likely(nm_basename_filter[bh & (NM_FILTER_SIZE - 1)] < 255))
                    nm_basename_filter[bh & (NM_FILTER_SIZE - 1)]++;

                irule->v_dev = inherited_dev;
                irule->v_statfs = inherited_statfs;
                hash_add_rcu(nomount_rules_ht, &irule->vpath_node, irule->v_hash);
                atomic_inc(&nm_active_rules);
                if (atomic_read(&nm_active_rules) == 1) static_branch_enable(&nomount_active_rules);
            } else {
                kfree(irule);
            }
        }
    }

    if (likely(err == 0)) {
        rule->v_dev = inherited_dev;
        rule->v_statfs = inherited_statfs;
    }

    return err;
}

/*** Rule Operations ***/

static int __nomount_add_rule(const char *v_path, const char *r_path, u16 v_len, u16 r_len, u32 flags)
{
    struct nomount_rule *rule = NULL, *existing, *victim = NULL;
    struct path path_main, r_path_struct_main;
    struct dentry *r_path_dentry = NULL;
    char *slash;
    const char *b_name;
    u32 hash, b_hash;
    int err = 0;
    bool v_path_exists = false; 
    bool is_whiteout = (flags & NM_FLAG_WHITEOUT);
    size_t total_size;

    if (!v_path || (!r_path && !is_whiteout)) return -EINVAL;

    hash = full_name_hash(NULL, v_path, v_len);

    if (is_whiteout) r_len = 0;
    total_size = sizeof(struct nomount_rule) + v_len + 1 + r_len + 1;

    rule = kmalloc(total_size, GFP_KERNEL);
    if (!rule) return -ENOMEM;

    rule->r_len = r_len;
    rule->v_len = v_len;

    memcpy(nm_get_vpath(rule), v_path, v_len);
    nm_get_vpath(rule)[v_len] = '\0';

    if (is_whiteout) {
        nm_get_rpath(rule)[0] = '\0';
    } else {
        memcpy(nm_get_rpath(rule), r_path, r_len);
        nm_get_rpath(rule)[r_len] = '\0';
    }

    INIT_HLIST_NODE(&rule->vpath_node);

    slash = strrchr(nm_get_vpath(rule), '/');
    b_name = slash ? slash + 1 : nm_get_vpath(rule);
    rule->b_offset = (u16)(b_name - nm_get_vpath(rule));
    b_hash = full_name_hash(NULL, nm_get_basename(rule), rule->v_len - rule->b_offset);
    rule->v_hash = hash;
    rule->flags = flags;

    if (!is_whiteout && kern_path(nm_get_rpath(rule), LOOKUP_FOLLOW, &r_path_struct_main) == 0) {
        struct inode *r_inode = d_backing_inode(r_path_struct_main.dentry);
        if (S_ISDIR(r_inode->i_mode)) rule->flags |= NM_FLAG_IS_DIR;
        nomount_hijack_superblock(r_path_struct_main.dentry->d_sb);
        nomount_hijack_rule_inode(rule, r_inode, false);
        nomount_hijack_dentry(r_path_struct_main.dentry, rule);
        r_path_dentry = dget(r_path_struct_main.dentry);
        path_put(&r_path_struct_main);
    }

    if (kern_path(nm_get_vpath(rule), LOOKUP_FOLLOW, &path_main) == 0) {
        struct inode *v_inode = d_backing_inode(path_main.dentry);
        rule->v_ino = v_inode->i_ino;
        rule->v_dev = path_main.dentry->d_sb->s_dev;
        if (path_main.dentry->d_sb->s_op->statfs) {
            path_main.dentry->d_sb->s_op->statfs(path_main.dentry, &rule->v_statfs);
        } else {
            memset(&rule->v_statfs, 0, sizeof(struct kstatfs));
            rule->v_statfs.f_type = path_main.dentry->d_sb->s_magic;
        }

        nomount_hijack_superblock(path_main.dentry->d_sb);
        if (is_whiteout) nomount_hijack_rule_inode(rule, v_inode, true);
        nomount_hijack_dentry(path_main.dentry, rule);
        path_put(&path_main);
        v_path_exists = true;
        nm_debug("Resolved physical backing for %s (ino: %lu)\n", nm_get_vpath(rule), rule->v_ino);
    } else {
        rule->v_ino = (unsigned long)hash;
    }

    mutex_lock(&nomount_write_mutex);
    hash_for_each_possible(nomount_rules_ht, existing, vpath_node, hash) {
        if (existing->v_hash == hash && existing->v_len == v_len &&
             memcmp(nm_get_vpath(existing), nm_get_vpath(rule), v_len) == 0) {
            hash_del_rcu(&existing->vpath_node);
            if (likely(nm_basename_filter[b_hash & (NM_FILTER_SIZE - 1)] > 0))
                nm_basename_filter[b_hash & (NM_FILTER_SIZE - 1)]--;
            atomic_dec(&nm_active_rules);
            victim = existing;
            nm_info("Shadowing existing rule for: %s\n", nm_get_vpath(rule));
            break;
        }
    }

    if (is_whiteout || !v_path_exists) {
        err = nomount_generate_virtual_topology(rule);
        if (err != 0) {
            mutex_unlock(&nomount_write_mutex);
            if (r_path_dentry) dput(r_path_dentry);
            kfree(rule); 
            return err;
        }
    }

    if (r_path_dentry)
        __nomount_collect_parents(rule, r_path_dentry);

    hash_add_rcu(nomount_rules_ht, &rule->vpath_node, hash);

    if (likely(nm_basename_filter[b_hash & (NM_FILTER_SIZE - 1)] < 255))
        nm_basename_filter[b_hash & (NM_FILTER_SIZE - 1)]++;

    atomic_inc(&nm_active_rules);
    if (atomic_read(&nm_active_rules) == 1) static_branch_enable(&nomount_active_rules);
    mutex_unlock(&nomount_write_mutex);

    if (unlikely(victim)) {
        synchronize_rcu();
        kfree(victim);
    }

    if (is_whiteout)
        nm_info("Successfully added whiteout rule: %s\n", nm_get_vpath(rule));
    else
        nm_info("Successfully added injection rule: %s -> %s\n", nm_get_vpath(rule), nm_get_rpath(rule));

    return 0;
}

static void __nomount_del_rule(const char *v_path, size_t v_len, struct hlist_head *r_victims, struct list_head *d_victims)
{
    struct nomount_rule *rule;
    u32 bh, hash = full_name_hash(NULL, v_path, v_len);

    hash_for_each_possible(nomount_rules_ht, rule, vpath_node, hash) {
        if (rule->v_hash == hash && rule->v_len == v_len &&
             memcmp(nm_get_vpath(rule), v_path, v_len) == 0) {
            hash_del_rcu(&rule->vpath_node);
            atomic_dec(&nm_active_rules);
            if (atomic_read(&nm_active_rules) == 0) static_branch_disable(&nomount_active_rules);
            hlist_add_head(&rule->vpath_node, r_victims);
            if (rule->parent_dir)
                __nomount_delete_child_locked(rule->parent_dir, hash, d_victims);

            bh = full_name_hash(NULL, nm_get_basename(rule), rule->v_len - rule->b_offset);
            if (likely(nm_basename_filter[bh & (NM_FILTER_SIZE - 1)] > 0))
                nm_basename_filter[bh & (NM_FILTER_SIZE - 1)]--;
            break;
        }
    }
}

static void __nomount_clear_all(void)
{
    struct nomount_rule *rule;
    struct nomount_dir_node *dir_node, *tmp_dir;
    struct nomount_uid_node *uid_node;
    struct hlist_node *hlist_tmp;
    struct nm_child_array *array;
    HLIST_HEAD(rule_victims);
    LIST_HEAD(dir_victims);
    HLIST_HEAD(uid_victims);
    int bkt;

    hash_for_each_safe(nomount_rules_ht, bkt, hlist_tmp, rule, vpath_node) {
        hash_del_rcu(&rule->vpath_node);
        hlist_add_head(&rule->vpath_node, &rule_victims);
    }

    hash_for_each_safe(nomount_uid_ht, bkt, hlist_tmp, uid_node, node) {
        hash_del_rcu(&uid_node->node);
        hlist_add_head(&uid_node->node, &uid_victims);
    }

    list_for_each_entry_safe(dir_node, tmp_dir, &nomount_all_dirs_list, list) {
        list_del(&dir_node->list);
        array = rcu_dereference_protected(dir_node->child_array, 1);
        if (array && atomic_dec_and_test(&array->refcnt)) kfree_rcu(array, rcu);
        if (dir_node->is_private) list_del_rcu(&dir_node->private_list);
        list_add_tail(&dir_node->list, &dir_victims);
    }

    atomic_set(&nm_active_rules, 0);
    atomic_set(&nm_active_dirs, 0);
    atomic_set(&nm_active_uids, 0);
    static_branch_disable(&nomount_active_rules);
    static_branch_disable(&nomount_active_dirs);
    static_branch_disable(&nomount_active_uids);
    INIT_LIST_HEAD(&nomount_private_dirs_list);
    INIT_LIST_HEAD(&nomount_all_dirs_list);
    memset(nm_basename_filter, 0, NM_FILTER_SIZE);
    synchronize_rcu();

    list_for_each_entry_safe(dir_node, tmp_dir, &dir_victims, list) {
        nomount_restore_dir_node(dir_node);
        kfree(dir_node->dir_path);
        kmem_cache_free(nm_dir_cachep, dir_node);
    }
    hlist_for_each_entry_safe(rule, hlist_tmp, &rule_victims, vpath_node) {
        nomount_restore_physical_inode(rule);
        kfree(rule);
    }
    hlist_for_each_entry_safe(uid_node, hlist_tmp, &uid_victims, node) {
        kmem_cache_free(nm_uid_cachep, uid_node);
    }

    nomount_restore_superblocks();
}

/*** Generic Netlink API ***/

static struct genl_family nomount_genl_family;

static int nomount_genl_add_rule(struct sk_buff *skb, struct genl_info *info)
{
    if (info->attrs[NOMOUNT_ATTR_PAYLOAD]) {
        struct nlattr *attr = info->attrs[NOMOUNT_ATTR_PAYLOAD];
        const char *data = nla_data(attr), *raw_v_ptr, *raw_r_ptr;
        int len = nla_len(attr);
        int pos = 0, err = 0;

        while (pos + 8 <= len) {
            u32 flags = get_unaligned((const u32 *)(data + pos));
            u16 vp_len = get_unaligned((const u16 *)(data + pos + 4));
            u16 rp_len = get_unaligned((const u16 *)(data + pos + 6));
            pos += 8;

            if (pos + vp_len + rp_len > len) break;
            if (unlikely(vp_len >= PATH_MAX || rp_len >= PATH_MAX)) break;

            raw_v_ptr = data + pos;  pos += vp_len;
            raw_r_ptr = data + pos;  pos += rp_len;
            err = __nomount_add_rule(raw_v_ptr, raw_r_ptr, vp_len, rp_len, flags);
            if (err) {
                nm_err("Failed to inject rule batch entry (err: %d). Skipping.\n", err);
            }
        }
        return 0;

    } else if (info->attrs[NOMOUNT_ATTR_VIRTUAL_PATH] && info->attrs[NOMOUNT_ATTR_REAL_PATH]) {
        char *v_str = nla_data(info->attrs[NOMOUNT_ATTR_VIRTUAL_PATH]);
        char *r_str = nla_data(info->attrs[NOMOUNT_ATTR_REAL_PATH]);
        u32 flags = info->attrs[NOMOUNT_ATTR_FLAGS] ? nla_get_u32(info->attrs[NOMOUNT_ATTR_FLAGS]) : 0;
        return __nomount_add_rule(v_str, r_str, strlen(v_str), strlen(r_str), flags);
    }

    return -EINVAL;
}

static int nomount_genl_del_rule(struct sk_buff *skb, struct genl_info *info)
{
    struct nomount_rule *rule;
    struct nomount_dir_node *dir_node, *tmp_dir;
    struct hlist_node *tmp_r;
    HLIST_HEAD(r_victims);
    LIST_HEAD(d_victims);

    if (info->attrs[NOMOUNT_ATTR_PAYLOAD]) {
        struct nlattr *attr = info->attrs[NOMOUNT_ATTR_PAYLOAD];
        const char *data = nla_data(attr);
        int len = nla_len(attr);
        int pos = 0;

        mutex_lock(&nomount_write_mutex);
        while (pos + 2 <= len) {
            u16 vp_len = get_unaligned((const u16 *)(data + pos));
            pos += 2; if (pos + vp_len > len) break;
            __nomount_del_rule(data + pos, vp_len, &r_victims, &d_victims);
            pos += vp_len;
        }
        mutex_unlock(&nomount_write_mutex);
    } else if (info->attrs[NOMOUNT_ATTR_VIRTUAL_PATH]) {
        char *v_path = nla_data(info->attrs[NOMOUNT_ATTR_VIRTUAL_PATH]);
        mutex_lock(&nomount_write_mutex);
        __nomount_del_rule(v_path, strlen(v_path), &r_victims, &d_victims);
        mutex_unlock(&nomount_write_mutex);
    } else {
        return -EINVAL;
    }

    if (hlist_empty(&r_victims)) return -ENOENT;
    synchronize_rcu();

    list_for_each_entry_safe(dir_node, tmp_dir, &d_victims, list) {
        nomount_restore_dir_node(dir_node);
        kfree(dir_node->dir_path);
        kmem_cache_free(nm_dir_cachep, dir_node);
    }
    hlist_for_each_entry_safe(rule, tmp_r, &r_victims, vpath_node) {
        nm_info("Deleted rule for: %s\n", nm_get_vpath(rule));
        nomount_restore_physical_inode(rule);
        kfree(rule);
    }

    return 0;
}

static int nomount_genl_clear_rules(struct sk_buff *skb, struct genl_info *info)
{
    mutex_lock(&nomount_write_mutex);
    __nomount_clear_all();
    mutex_unlock(&nomount_write_mutex);
    nm_info("Cleared all active rules and UIDs\n");
    return 0;
}

static int nomount_genl_dump_rules(struct sk_buff *skb, struct netlink_callback *cb)
{
    struct nomount_rule *rule;
    int start_idx = cb->args[0], bkt, idx = 0;
    void *hdr;

    rcu_read_lock();
    hash_for_each_rcu(nomount_rules_ht, bkt, rule, vpath_node) {
        if (idx < start_idx) { idx++; continue; }

        hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
                          &nomount_genl_family, NLM_F_MULTI, NM_CMD_GET_LIST);
        if (!hdr) break; /* skb is full, break and resume later */

        if (nla_put_string(skb, NOMOUNT_ATTR_VIRTUAL_PATH, nm_get_vpath(rule)) ||
               nla_put_string(skb, NOMOUNT_ATTR_REAL_PATH, nm_get_rpath(rule)) ||
               nla_put_u32(skb, NOMOUNT_ATTR_FLAGS, rule->flags)) {
            genlmsg_cancel(skb, hdr);
            break;
        }
        genlmsg_end(skb, hdr);
        idx++;
    }
    rcu_read_unlock();

    cb->args[0] = idx; 
    return skb->len;
}

static int nomount_genl_add_uid(struct sk_buff *skb, struct genl_info *info)
{
    unsigned int uid;
    struct nomount_uid_node *entry;

    if (!info->attrs[NOMOUNT_ATTR_UID])
        return -EINVAL;

    uid = nla_get_u32(info->attrs[NOMOUNT_ATTR_UID]);

    if (nomount_is_uid_blocked(uid)) 
        return -EEXIST;

    entry = kmem_cache_alloc(nm_uid_cachep, GFP_KERNEL);
    if (!entry) return -ENOMEM;
    entry->uid = uid;
    
    mutex_lock(&nomount_write_mutex);
    hash_add_rcu(nomount_uid_ht, &entry->node, uid);
    atomic_inc(&nm_active_uids);
    if (atomic_read(&nm_active_uids) == 1) static_branch_enable(&nomount_active_uids);
    mutex_unlock(&nomount_write_mutex);
    
    nm_info("Successfully added blocked UID: %u\n", uid);
    return 0;
}

static int nomount_genl_del_uid(struct sk_buff *skb, struct genl_info *info)
{
    unsigned int uid;
    struct nomount_uid_node *entry;
    struct hlist_node *tmp;
    int bkt;
    bool found = false;

    if (!info->attrs[NOMOUNT_ATTR_UID])
        return -EINVAL;

    uid = nla_get_u32(info->attrs[NOMOUNT_ATTR_UID]);

    mutex_lock(&nomount_write_mutex);
    hash_for_each_safe(nomount_uid_ht, bkt, tmp, entry, node) {
        if (entry->uid == uid) {
            hash_del_rcu(&entry->node);
            found = true;
            break; 
        }
    }
    atomic_dec(&nm_active_uids);
    if (atomic_read(&nm_active_uids) == 0) static_branch_disable(&nomount_active_uids);
    mutex_unlock(&nomount_write_mutex);

    if (found && entry) {
        synchronize_rcu();
        kmem_cache_free(nm_uid_cachep, entry);
    }

    nm_info("Successfully remove blocked UID: %u\n", uid);
    return found ? 0 : -ENOENT;
}

static int nomount_genl_get_version(struct sk_buff *skb, struct genl_info *info)
{
    struct sk_buff *msg;
    void *hdr;
    int ret;

    msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!msg) return -ENOMEM;

    hdr = genlmsg_put_reply(msg, info, &nomount_genl_family, 0, info->genlhdr->cmd);
    if (!hdr) {
        nlmsg_free(msg);
        return -EMSGSIZE;
    }

    ret = nla_put_string(msg, NOMOUNT_ATTR_VERSION, NOMOUNT_VERSION);
    if (ret) {
        genlmsg_cancel(msg, hdr);
        nlmsg_free(msg);
        return ret;
    }

    genlmsg_end(msg, hdr);
    return genlmsg_reply(msg, info);
}

static const struct nla_policy nomount_genl_policy[NOMOUNT_ATTR_MAX + 1] = {
    [NOMOUNT_ATTR_VIRTUAL_PATH] = { .type = NLA_NUL_STRING, .len = PATH_MAX },
    [NOMOUNT_ATTR_REAL_PATH]    = { .type = NLA_NUL_STRING, .len = PATH_MAX },
    [NOMOUNT_ATTR_FLAGS]        = { .type = NLA_U32 },
    [NOMOUNT_ATTR_UID]          = { .type = NLA_U32 },
    [NOMOUNT_ATTR_VERSION]      = { .type = NLA_NUL_STRING },
    [NOMOUNT_ATTR_PAYLOAD]      = { .type = NLA_BINARY },
};

static const struct genl_ops nomount_genl_ops[] = {
    { .cmd = NM_CMD_ADD_RULE, .flags = GENL_ADMIN_PERM, .doit = nomount_genl_add_rule, NM_OPS_POLICY(nomount_genl_policy) },
    { .cmd = NM_CMD_DEL_RULE, .flags = GENL_ADMIN_PERM, .doit = nomount_genl_del_rule, NM_OPS_POLICY(nomount_genl_policy) },
    { .cmd = NM_CMD_CLEAR_ALL, .flags = GENL_ADMIN_PERM, .doit = nomount_genl_clear_rules, NM_OPS_POLICY(nomount_genl_policy) },
    { .cmd = NM_CMD_ADD_UID, .flags = GENL_ADMIN_PERM, .doit = nomount_genl_add_uid, NM_OPS_POLICY(nomount_genl_policy) },
    { .cmd = NM_CMD_DEL_UID, .flags = GENL_ADMIN_PERM, .doit = nomount_genl_del_uid, NM_OPS_POLICY(nomount_genl_policy) },
    { .cmd = NM_CMD_GET_LIST, .flags = GENL_ADMIN_PERM, .dumpit = nomount_genl_dump_rules, NM_OPS_POLICY(nomount_genl_policy) },
    { .cmd = NM_CMD_GET_VERSION, .flags = GENL_ADMIN_PERM, .doit = nomount_genl_get_version, NM_OPS_POLICY(nomount_genl_policy) },
};

static struct genl_family nomount_genl_family = {
    .name = NOMOUNT_GENL_NAME,
    .version = NOMOUNT_GENL_VERSION,
    .maxattr = NOMOUNT_ATTR_MAX,
    NM_FAMILY_POLICY(nomount_genl_policy)
    .netnsok = true,
    .module = THIS_MODULE,
    .ops = nomount_genl_ops,
    .n_ops = ARRAY_SIZE(nomount_genl_ops),
};

static int __init nomount_init(void) {
    int ret;

    hash_init(nomount_sb_ht);
    hash_init(nomount_rules_ht);
    hash_init(nomount_uid_ht);

    nm_dir_cachep = kmem_cache_create("nm_dirs", sizeof(struct nomount_dir_node), 0, SLAB_HWCACHE_ALIGN, NULL);
    nm_uid_cachep = kmem_cache_create("nm_uids", sizeof(struct nomount_uid_node), 0, SLAB_HWCACHE_ALIGN, NULL);

    if (!nm_dir_cachep || !nm_uid_cachep) {
        nm_err("Failed to allocate memory slab caches\n");
        if (nm_dir_cachep) kmem_cache_destroy(nm_dir_cachep);
        if (nm_uid_cachep) kmem_cache_destroy(nm_uid_cachep);
        return -ENOMEM;
    }

    ret = genl_register_family(&nomount_genl_family);
    if (ret) {
        nm_err("Failed to register Generic Netlink family (err: %d)\n", ret);
        kmem_cache_destroy(nm_dir_cachep);
        kmem_cache_destroy(nm_uid_cachep);
        return ret;
    }

    nm_info("Loaded successfully\n");
    return 0;
}

fs_initcall(nomount_init);

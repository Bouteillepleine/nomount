# NoMount - Detail Hook Architecture & Integration

This document details the hook architecture used by NoMount within the Linux Virtual File System (VFS).


## 1. Initialization and Configuration (`Kconfig` & `Makefile`)
*   **Files:** `fs/Kconfig`, `fs/Makefile`
*   **Purpose:** Register NoMount in kernel.
*   **Mechanism:** Adds the `CONFIG_NOMOUNT` flag to allow enabling/disabling the module during kernel configuration (`menuconfig`) and tells the build system to include `nomount.o` in the final link.
*   **Integration:**:

#### `fs/Kconfig`:

```diff
diff --git a/fs/Kconfig b/fs/Kconfig
index c34b9d4e0..8ec1f2b07 100644
--- a/fs/Kconfig
+++ b/fs/Kconfig
@@ -xxx,xx +xxx,xx @@

+config NOMOUNT
+	bool "NoMount Path Redirection Subsystem"
+	default y
+	help
+	  NoMount allows path redirection and virtual file injection
+	  without mounting filesystems. Useful for systemless modifications.
+
 endmenu
```

#### `fs/Makefile`:

```diff
diff --git a/fs/Makefile b/fs/Makefile
--- a/fs/Makefile
+++ b/fs/Makefile
@@ -xx,x +xx,x @@
 
+obj-$(CONFIG_NOMOUNT) += nomount.o
+
 obj-$(CONFIG_PROC_FS) += proc_namespace.o

```

---

## 2. Path Lookup, Access Control, and Permissions.
*    **Files:** `fs/namei.c`
*    **Hooks:** `getname_flags`, `getname_kernel` and `inode_permission`
*    **Purpose:** Intercept text strings (paths) originating from both Userspace and Kernelspace before the VFS converts them into physical structures (`dentry`/`inode`). Additionally, ensure that injected files can be traversed and read while correctly simulating the typical attributes of system partitions.
*   **Mechanism:**
    *   In `namei.c`, `nomount_getname_hook` is executed immediately after the path string is allocated in the kernel. `getname_flags` intercepts standard application traffic, while `getname_kernel` catches internal system requests (e.g., `request_firmware`). If the path matches an active rule, the original string is replaced with the actual path of the redirected file. The rest of the kernel processes the call without knowing that it was tricked.
    *   In `namei.c`, the `nomount_allow_access` hook forces a return of `0` (Success) to prevent native DAC/MAC checks (like SELinux) from blocking access to our injected folders.
*   **Integration:**

#### `fs/namei.c`:

```diff
diff --git a/fs/namei.c b/fs/namei.c
--- a/fs/namei.c
+++ b/fs/namei.c
@@ -xxx,xx +xxx,xx @@
 
 #define EMBEDDED_NAME_MAX	(PATH_MAX - offsetof(struct filename, iname))
 
+#ifdef CONFIG_NOMOUNT
+extern struct filename *nomount_handle_getname(struct filename *name);
+extern int nomount_handle_permission(struct inode *inode, int mask);
+#endif
+
 struct filename *
 getname_flags(const char __user *filename, int flags, int *empty)
 {
@@ -xxx,xx +xxx,xx @@ getname_flags(const char __user *filename, int flags, int *empty)
 
 	result->uptr = filename;
 	result->aname = NULL;
+#ifdef CONFIG_NOMOUNT
+	if (!IS_ERR(result)) {
+		result = nomount_handle_getname(result);
+	}
+#endif
 	audit_getname(result);
 	return result;
 }
@@ -xxx,xx +xxx,xx @@ getname_kernel(const char * filename)
 	result->uptr = NULL;
 	result->aname = NULL;
 	result->refcnt = 1;
+#ifdef CONFIG_NOMOUNT
+	if (!IS_ERR(result)) {
+		result = nomount_handle_getname(result);
+	}
+#endif
 	audit_getname(result);
 
 	return result;
@@ -xxx,xx +xxx,xx @@ int inode_permission(struct inode *inode, int mask)
 {
 	int retval;
 
+#ifdef CONFIG_NOMOUNT
+	int nm_perm = nomount_handle_permission(inode, mask);
+	if (unlikely(nm_perm < 0)) return nm_perm;
+	if (unlikely(nm_perm > 0)) return 0;
+#endif
+
 	retval = sb_permission(inode->i_sb, inode, mask);
 	if (retval)
 		return retval;
```

---

## 3. Metadata Spoofing (Stat & Mmap)
To be undetectable, the metadata of the files and file systems must match their virtual location.

*   **Memory Maps (`fs/proc/task_mmu.c`):**
    *   **Hook:** `show_map_vma`
    *   **Mechanism:** When a process reads `/proc/self/maps`, the kernel prints the loaded libraries into memory. The `nomount_spoof_mmap_metadata` hook replaces the raw device and inode just before they are printed to the `seq_file`.
	*   **Integration:**

#### `fs/proc/task_mmu.c`:

```diff
diff --git a/fs/proc/task_mmu.c b/fs/proc/task_mmu.c
--- a/fs/proc/task_mmu.c
+++ b/fs/proc/task_mmu.c
@@ -xxx,xx +xxx,xx @@ static void show_vma_header_prefix(struct seq_file *m,
 	seq_putc(m, ' ');
 }
 
+#ifdef CONFIG_NOMOUNT
+extern bool nomount_spoof_mmap_metadata(struct inode *inode, dev_t *dev, unsigned long *ino);
+#endif
+
 static void
 show_map_vma(struct seq_file *m, struct vm_area_struct *vma)
 {
@@ -xxx,xx +xxx,xx @@ show_map_vma(struct seq_file *m, struct vm_area_struct *vma)
 		struct inode *inode = file_inode(vma->vm_file);
 		dev = inode->i_sb->s_dev;
 		ino = inode->i_ino;
+#ifdef CONFIG_NOMOUNT
+		nomount_spoof_mmap_metadata(inode, &dev, &ino);
+#endif
 		pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;
 	}

```

---

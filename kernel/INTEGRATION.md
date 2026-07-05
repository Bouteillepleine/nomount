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

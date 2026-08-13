# NoMount - Kernel Integration

This section contains everything related to the integration of NoMount into the kernel. 

### Integration:

If you want to integrate NoMount in your kernel automatically without problems, you can use the script:

```bash
curl https://raw.githubusercontent.com/maxsteeel/nomount/refs/heads/dev/kernel/setup.sh | bash -
```

To integrate a specific branch:

```bash
curl https://raw.githubusercontent.com/maxsteeel/nomount/refs/heads/dev/kernel/setup.sh | bash -s dev
```

In case to you want to integrate it manually, here the steps:

1. Integrate NoMount:

Add this to fs/Kconfig:

```kconfig
source "fs/nomount/Kconfig"
```

And add this to fs/Makefile:

```make
obj-$(CONFIG_NOMOUNT) += nomount/
```

2. Copy the necessary files:

Transfer the NoMount code (src/) to the fs directory (fs/nomount/) of your kernel:

```bash
mkdir -p fs/nomount
cp path/to/nomount/kernel/src/* <your_kernel_source>/fs/nomount
```

3. Configure and compile NoMount:

Enable NoMount in your defconfig or via menuconfig:

```
CONFIG_NOMOUNT=y
```

Then compile your kernel as usual. If you followed the steps correctly, at the end of the compilation you will have a kernel with NoMount integrated!


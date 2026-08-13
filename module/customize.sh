ui_print " "
ui_print "======================================="
ui_print "                NoMount                "
ui_print "  Native Kernel Injection Metamodule   "
ui_print "======================================="
ui_print " "

ui_print "- Device Architecture: $ARCH"

if [ ! -f "$MODPATH/bin/nm-$ARCH" ]; then
  abort "! Unsupported architecture: $ARCH"
fi
mv "$MODPATH/bin/nm-$ARCH" "$MODPATH/bin/nm"
set_perm "$MODPATH/bin/nm" 0 0 0755
rm -rf "$MODPATH"/bin/nm-*

install_lkm() {
  local module_path="$1"
  if command -v ksud >/dev/null 2>&1; then
    ksud insmod "$module_path"
    return $?
  fi
  insmod "$module_path"
  return $?
}

KVER=$(uname -r | cut -d'.' -f1,2)
AKVER=$(uname -r | grep -oE 'android[0-9]+')

if [ -n "$AKVER" ]; then
  ui_print "- Detected Kernel: $KVER ($AKVER branch)"
else
  ui_print "- Detected Kernel: $KVER (Custom/Unknown branch)"
fi

NOMOUNT_LOADED=false
ui_print "- Checking Kernel support via Internal API..."
if "$MODPATH/bin/nm" version > /dev/null 2>&1; then
  ui_print "  [OK] NoMount Internal API detected (Built-in)."
  NOMOUNT_LOADED=true
  rm -rf "$MODPATH/lkm"
else
  ui_print "  [*] Built-in support not found. Attempting LKM injection..."
  EXACT_MATCH="$MODPATH/lkm/nomount-${AKVER}-${KVER}.ko"
  if [ -n "$AKVER" ] && [ -f "$EXACT_MATCH" ]; then
    ui_print "  [*] Trying exact match: $(basename "$EXACT_MATCH")"
    if install_lkm "$EXACT_MATCH" && "$MODPATH/bin/nm" version > /dev/null 2>&1; then
      mv "$EXACT_MATCH" "$MODPATH/lkm/nomount.ko"
      NOMOUNT_LOADED=true
    else
      rmmod nomount 2>/dev/null
    fi
  fi

  if [ "$NOMOUNT_LOADED" = false ]; then
    for mod in "$MODPATH"/lkm/nomount*-${KVER}.ko; do
      if [ ! -f "$mod" ] || [ "$mod" = "$EXACT_MATCH" ]; then continue; fi
      ui_print "  [*] Trying fallback: $(basename "$mod")"
      if install_lkm "$mod" && "$MODPATH/bin/nm" version > /dev/null 2>&1; then
        mv "$mod" "$MODPATH/lkm/nomount.ko"
        NOMOUNT_LOADED=true
        break
      else
        rmmod nomount 2>/dev/null
      fi
    done
  fi

  rm -f "$MODPATH"/lkm/nomount-*.ko
fi

if [ "$NOMOUNT_LOADED" = true ]; then
  ui_print "  [OK] System is ready for injection."
else
  ui_print " "
  ui_print "***************************************************"
  ui_print "* [!] WARNING: KERNEL DRIVER NOT DETECTED         *"
  ui_print "***************************************************"
  ui_print "* NoMount Internal API missing/unresponsive and   *"
  ui_print "* no compatible loadable kernel module was found. *"
  ui_print "*                                                 *"
  ui_print "* This module will NOT FUNCTION until you flash   *"
  ui_print "* a Kernel compiled with CONFIG_NOMOUNT=y         *"
  ui_print "***************************************************"
  ui_print " "
  abort "! Kernel module not detected"
fi

NOMOUNT_DATA="/data/adb/nomount"
mkdir -p "$NOMOUNT_DATA"
rm -f "$NOMOUNT_DATA/.booting"

ui_print "- Installation complete."

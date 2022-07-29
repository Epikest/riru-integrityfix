SKIPUNZIP=1

MODID="${MODPATH##*/}"
MAGISKTMP="$(magisk --path)"
[ -z "$MAGISKTMP" ] && MAGISKTMP="/sbin"

# Extract verify.sh
ui_print "- Extracting verify.sh"
unzip -o "$ZIPFILE" 'verify.sh' -d "$TMPDIR" >&2
if [ ! -f "$TMPDIR/verify.sh" ]; then
  ui_print    "*********************************************************"
  ui_print    "! Unable to extract verify.sh!"
  ui_print    "! This zip may be corrupted, please try downloading again"
  abort "*********************************************************"
fi
. $TMPDIR/verify.sh

extract "$ZIPFILE" 'customize.sh' "$TMPDIR/.vunzip"
extract "$ZIPFILE" 'verify.sh' "$TMPDIR/.vunzip"

# Extract riru.sh

# Variables provided by riru.sh:
#
# RIRU_API: API version of installed Riru, 0 if not installed
# RIRU_MIN_COMPATIBLE_API: minimal supported API version by installed Riru, 0 if not installed or version < v23.2
# RIRU_VERSION_CODE: version code of installed Riru, 0 if not installed or version < v23.2
# RIRU_VERSION_NAME: version name of installed Riru, "" if not installed or version < v23.2

extract "$ZIPFILE" 'riru.sh' "$TMPDIR"
. $TMPDIR/riru.sh

# Functions from riru.sh
check_riru_version
enforce_install_from_magisk_app

# Check architecture
if [ "$ARCH" != "arm" ] && [ "$ARCH" != "arm64" ] && [ "$ARCH" != "x86" ] && [ "$ARCH" != "x64" ]; then
  abort "! Unsupported platform: $ARCH"
else
  ui_print "- Device platform: $ARCH"
fi

# Extract libs
ui_print "- Extracting module files"

extract "$ZIPFILE" 'module.prop' "$MODPATH"
# extract "$ZIPFILE" 'post-fs-data.sh' "$MODPATH"
# extract "$ZIPFILE" 'uninstall.sh' "$MODPATH"
extract "$ZIPFILE" 'classes.dex' "$MODPATH"
extract "$ZIPFILE" 'fingerprint.txt' "$MODPATH"
if [ -f "$MAGISKTMP/.magisk/modules/$MODID/fingerprint.txt" ]; then
    cp -af "$MAGISKTMP/.magisk/modules/$MODID/fingerprint.txt" "$MODPATH/fingerprint.txt"
fi

# Riru v24+ load files from the "riru" folder in the Magisk module folder
# This "riru" folder is also used to determine if a Magisk module is a Riru module

mkdir "$MODPATH/riru"
mkdir "$MODPATH/riru/lib"
mkdir "$MODPATH/riru/lib64"

if [ "$ARCH" = "arm" ] || [ "$ARCH" = "arm64" ]; then
  ui_print "- Extracting arm libraries"
  extract "$ZIPFILE" "lib/armeabi-v7a/lib$RIRU_MODULE_LIB_NAME.so" "$MODPATH/riru/lib" true

  if [ "$IS64BIT" = true ]; then
    ui_print "- Extracting arm64 libraries"
    extract "$ZIPFILE" "lib/arm64-v8a/lib$RIRU_MODULE_LIB_NAME.so" "$MODPATH/riru/lib64" true
  fi
fi

if [ "$ARCH" = "x86" ] || [ "$ARCH" = "x64" ]; then
  ui_print "- Extracting x86 libraries"
  extract "$ZIPFILE" "lib/x86/lib$RIRU_MODULE_LIB_NAME.so" "$MODPATH/riru/lib" true

  if [ "$IS64BIT" = true ]; then
    ui_print "- Extracting x64 libraries"
    extract "$ZIPFILE" "lib/x86_64/lib$RIRU_MODULE_LIB_NAME.so" "$MODPATH/riru/lib64" true
  fi
fi

# Riru pre-v24 uses "/system", "/data/adb/riru/modules" is used as the module list
# If "/data/adb/riru/modules/example" exists, Riru will try to load "/system/lib(64)/libriru_example.so

# If your module does not need to support Riru pre-v24, you can raise the value of "moduleMinRiruApiVersion" in "module.gradle"
# and remove this part

if [ "$RIRU_API" -lt 11 ]; then
  ui_print "- Using old Riru"
  mv "$MODPATH/riru" "$MODPATH/system"
  mkdir -p "/data/adb/riru/modules/$RIRU_MODULE_ID_PRE24"
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644

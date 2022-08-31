#!/system/bin/sh
# Conditional MagiskHide properties
MODDIR="${0%/*}"

maybe_set_prop() {
    local prop="$1"
    local contains="$2"
    local value="$3"

    if [[ "$(getprop "$prop")" == *"$contains"* ]]; then
        resetprop "$prop" "$value"
    fi
}

# Magisk recovery mode
maybe_set_prop ro.bootmode recovery unknown
maybe_set_prop ro.boot.mode recovery unknown
maybe_set_prop vendor.boot.mode recovery unknown

# MIUI cross-region flash
maybe_set_prop ro.boot.hwc CN GLOBAL
maybe_set_prop ro.boot.hwcountry China GLOBAL
maybe_set_prop sys.oem_unlock_allowed 1 0

resetprop --delete ro.build.selinux

# SELinux permissive
if [[ "$(cat /sys/fs/selinux/enforce)" == "0" ]]; then
    chmod 640 /sys/fs/selinux/enforce
    chmod 440 /sys/fs/selinux/policy
fi

if [ -f "$MODDIR/debug_log.txt" ]; then
    logcat PlayIntegrityFix:* *:S >"$MODDIR/debug_log.txt" &
fi

# Late props which must be set after boot_completed
{
    until [[ "$(getprop sys.boot_completed)" == "1" ]]; do
        sleep 1
    done

    # avoid breaking Realme fingerprint scanners
    resetprop ro.boot.flash.locked 1

    # avoid breaking Oppo fingerprint scanners
    resetprop ro.boot.vbmeta.device_state locked

    # avoid breaking OnePlus display modes/fingerprint scanners
    resetprop vendor.boot.verifiedbootstate green


    # Oneplus
    resetprop ro.is_ever_orange 0

    # Safetynet
    resetprop ro.boot.verifiedbootstate green
    resetprop ro.boot.veritymode enforcing
    resetprop vendor.boot.vbmeta.device_state locked

    # do unmount in Google Play Services
    while true; do
        sleep 3
        for i in 99999 $(pidof com.google.android.gms) $(pidof com.google.android.gms.unstable); do
            magisk magiskhide --do-unmount "$i"
        done
    done
}&

# Riru - Play Integrity Fix

- A workarround to pass SafetyNet / Play Integrity API on rooted devices with unlocked bootloader by injecting into `com.google.android.gms` and `com.google.android.gms.unstable`, preventing SafetyNet API from using hardware attestation and spoofing low Android fingerprint. 

- By default, the fingerprint is `google/marlin/marlin:7.1.2/NJH47F/4146041:user/release-keys`. Configure `fingerprint.txt` in module directory if you want to spoof with different fingerprint.

- This module is specially made for Magisk v23 or Magisk Delta users.

## Credit

- [kdrag0n/SafetyNet-Fix](https://github.com/kdrag0n/safetynet-fix) - SafetyNet Fix source code

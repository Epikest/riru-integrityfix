#!/usr/bin/env bash

src_dir="$(pwd)"

# Build Java code part
cd "$src_dir/java_module"
# Must always be release due to R8 requirement
chmod 777 ./gradlew
./gradlew assembleRelease || exit 1
unzip "$src_dir/java_module/app/build/outputs/apk/release/app-release.apk" classes.dex -d "$src_dir/riru/template/magisk_module"

# Build Riru module
cd "$src_dir/riru" && rm -fr out
chmod 777 ./gradlew
if [ "$1" == "cache" ]; then
    ./gradlew aR --build-cache || exit 1
else
    ./gradlew assembleRelease || exit 1
fi
    
./gradlew --stop

cd "$src_dir"
rm -rf "$src_dir/out"
mv -fT "$src_dir/riru/out" "$src_dir/out"

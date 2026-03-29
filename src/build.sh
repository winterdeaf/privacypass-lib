set -e

PRIVACYPASS_REV=48296d41

# Clone upstream privacypass at the pinned revision and apply compatibility patches.
# The result lands in vendor/privacypass, which is referenced by the [patch] table
# in Cargo.toml so that cargo uses the patched copy during the build.
if [ ! -d vendor/privacypass ]; then
    git clone https://github.com/raphaelrobert/privacypass vendor/privacypass
fi
git -C vendor/privacypass checkout "$PRIVACYPASS_REV"
patch -p1 -d vendor/privacypass < patches/privacypass-batched-compat.patch

cargo build --release
(cd wasm; bash build.sh)

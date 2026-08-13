#!/bin/sh
set -eu

GKI_ROOT=$(pwd)
REPO_URL="https://github.com/maxsteeel/nomount"
REPO_DIR="$GKI_ROOT/NoMount"

display_usage() {
    echo "Usage: $0 [--cleanup | <commit-or-tag>]"
    echo "  --cleanup:             Cleans up previous modifications made by the script (doesn't revert in-kernel patches)."
    echo "  <commit-or-tag>:       Sets up or updates NoMount to specified tag or commit."
    echo "  -h, --help:            Displays this usage information."
    echo "  (no args):             Sets up or updates NoMount environment to the latest tagged version."
}

initialize_variables() {
    if test -d "$GKI_ROOT/fs"; then
         FS_DIR="$GKI_ROOT/fs"
    else
         echo '[ERROR] "fs/" directory not found. Are you at the root of the kernel tree?'
         exit 127
    fi

    FS_MAKEFILE=$FS_DIR/Makefile
    FS_KCONFIG=$FS_DIR/Kconfig
}

perform_cleanup() {
    echo "[+] Cleaning up NoMount..."
    [ -L "$FS_DIR/nomount" ] && rm "$FS_DIR/nomount" && echo "[-] Symlink removed."
    grep -q "nomount" "$FS_MAKEFILE" && sed -i '/nomount/d' "$FS_MAKEFILE" && echo "[-] Makefile reverted."
    grep -q "fs/nomount/Kconfig" "$FS_KCONFIG" && sed -i '/fs\/nomount\/Kconfig/d' "$FS_KCONFIG" && echo "[-] Kconfig reverted."
    if [ -d "$REPO_DIR" ]; then
        rm -rf "$REPO_DIR" && echo "[-] NoMount directory deleted."
    fi
    echo "[+] Cleanup complete."
}

setup_nomount() {
    echo "[+] Setting up NoMount..."
    test -d "$REPO_DIR" || git clone "$REPO_URL" "$REPO_DIR" && echo "[+] Repository cloned."

    cd "$REPO_DIR"
    git stash >/dev/null 2>&1 || true && echo "[-] Stashed current changes."

    if [ "$(git branch --list dev)" ]; then
        git checkout dev --quiet && echo "[-] Switched to dev branch."
    elif [ "$(git branch --list master)" ]; then
        git checkout master --quiet && echo "[-] Switched to master branch."
    fi

    git pull --quiet && echo "[+] Repository updated."

    if [ -z "${1-}" ]; then
        LATEST_TAG=$(git describe --abbrev=0 --tags 2>/dev/null || echo "")
        if [ -n "$LATEST_TAG" ]; then
            git checkout "$LATEST_TAG" --quiet && echo "[-] Checked out latest tag ($LATEST_TAG)."
        else
            echo "[-] No tags found. Staying on default branch."
        fi
    else
        git checkout "$1" --quiet && echo "[-] Checked out $1." || echo "[-] Checkout default branch"
    fi

    CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "HEAD")
    if [ "$CURRENT_BRANCH" = "master" ] || [ "${1-}" = "master" ]; then
        echo "[+] Legacy version detected (master branch). Applying in-kernel hooks..."
        cd "$GKI_ROOT"

        if [ -f "Makefile" ]; then
            K_VER=$(grep -E '^VERSION\s*=' Makefile | tr -d ' ' | cut -d'=' -f2)
            K_PATCH=$(grep -E '^PATCHLEVEL\s*=' Makefile | tr -d ' ' | cut -d'=' -f2)
            FULL_KVER="${K_VER}.${K_PATCH}"

            PATCH_FILE="$REPO_DIR/kernel/patches/nomount_${FULL_KVER}_kernel_integration.patch"
            if [ -f "$PATCH_FILE" ]; then
                echo "[-] Found patch for kernel ${K_FULL_VER}. Applying..."
                patch -p1 < "$PATCH_FILE" || echo "[!] Warning: Patch failed or was already applied."
            else
                echo "[!] Error: No patch file found for kernel version ${K_FULL_VER}!"
                echo "    Expected path: $PATCH_FILE"
            fi
        else
            echo "[!] Error: Top-level Makefile not found. Cannot determine kernel version."
        fi
    fi

    cd "$FS_DIR"

    ln -sf "$(realpath --relative-to="$FS_DIR" "$REPO_DIR/kernel/src")" "nomount" && echo "[+] Symlink created (fs/nomount -> kernel/src)."
    grep -q "nomount" "$FS_MAKEFILE" || printf "\nobj-\$(CONFIG_NOMOUNT) += nomount/\n" >> "$FS_MAKEFILE" && echo "[+] Modified fs/Makefile."

    if grep -q "source \"fs/nomount/Kconfig\"" "$FS_KCONFIG"; then
        echo "[-] Kconfig already modified."
    else
        if grep -q "^endmenu" "$FS_KCONFIG"; then
            sed -i -e '/^endmenu/i\source "fs/nomount/Kconfig"' "$FS_KCONFIG"
        else
            echo 'source "fs/nomount/Kconfig"' >> "$FS_KCONFIG"
        fi
        echo "[+] Modified fs/Kconfig."
    fi

    echo '[+] NoMount Setup Done!'
}

if [ "$#" -eq 0 ]; then
    initialize_variables
    setup_nomount
elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    display_usage
elif [ "$1" = "--cleanup" ]; then
    initialize_variables
    perform_cleanup
else
    initialize_variables
    setup_nomount "$@"
fi

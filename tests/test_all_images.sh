#!/usr/bin/env bash
#set -x

IMAGES_REPO="https://github.com/ntfsprogs-plus/ntfs_corrupted_images.git"
REPO_NAME="ntfs_corrupted_images"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd) || exit 1
FSCK_PATH=${SCRIPT_DIR}/image_runner/
NTFSCK_IMAGE_TEST_BINARY=${NTFSCK_IMAGE_TEST_BINARY:-${SCRIPT_DIR}/../src/ntfsck}
export FSCK_PATH NTFSCK_IMAGE_TEST_BINARY
CHECKOUT_BR=${1:-"main"}

echo "Download corrupted images..."
echo ""

if [ -d "${REPO_NAME}" ]; then
	if ! git -C "${REPO_NAME}" fetch; then
		echo "git fetch FAILED. exit"
		exit 1
	fi
else
	git clone "${IMAGES_REPO}" "${REPO_NAME}" || exit 1
fi

if [ "${CHECKOUT_BR}" != "main" ]; then
	echo "Checking out ${CHECKOUT_BR}... "

	if ! git -C "${REPO_NAME}" checkout "origin/${CHECKOUT_BR}" -b "${CHECKOUT_BR}"; then
		git -C "${REPO_NAME}" checkout "${CHECKOUT_BR}" || exit 1
	fi
else
	echo "Rebasing latest origin/main... "
	git -C "${REPO_NAME}" checkout main &&
		git -C "${REPO_NAME}" rebase origin/main || exit 1
fi

if ! (cd "${REPO_NAME}" && ./test_all.sh); then
	for logfile in "${REPO_NAME}"/test_results/*_test_*.log; do
		[ -f "${logfile}" ] || continue
		tail -n 80 "${logfile}"
	done
	exit 1
fi

echo "Successfully tested corrupted images"

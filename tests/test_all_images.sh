#!/usr/bin/env bash
#set -x

IMAGES_REPO="https://github.com/ntfsprogs-plus/ntfs_corrupted_images.git"
REPO_NAME="ntfs_corrupted_images"
PWD=`pwd`
FSCK_PATH=$PWD/../src/
CHECKOUT_BR=${1:-"main"}

echo "Download corrupted images..."
echo ""

if [ -d "${REPO_NAME}" ]; then
	cd ${REPO_NAME}
	git fetch
	if [ $? -ne 0 ]; then
		echo "git fetch FAILED. exit"
		exit
	fi
	cd ..
else
	git clone ${IMAGES_REPO} ${REPO_NAME}
fi

if [ ${CHECKOUT_BR} != "main" ]; then
	echo "Checking out ${CHECKOUT_BR}... "

	cd ${REPO_NAME} && git checkout origin/${CHECKOUT_BR} -b ${CHECKOUT_BR}
	RET=$?
	if [ ${RET} -ne 0 ]; then
		git checkout ${CHECKOUT_BR}
		RET=$?
	fi
	cd ..
else
	echo "Rebasing latest origin/main... "
	cd ${REPO_NAME} && git checkout main && git rebase origin/main
	RET=$?
	cd ..
fi

if [ $RET -ne 0 ]; then
	echo "Failed to checkout or rebase ${CHECKOUT_BR}"
	exit
fi

/bin/bash -c "cd ${REPO_NAME} && ENV=${FSCK_PATH} ./test_all.sh 2> /dev/null"
RET=$?
if [ $RET -ne 0 ]; then
	exit 1
fi

echo "Sucess to test corrupted images"
#rm -rf ${REPO_NAME}

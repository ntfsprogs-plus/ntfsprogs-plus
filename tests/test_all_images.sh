#!/usr/bin/env bash
#set -x

IMAGES_REPO="https://github.com/ntfsprogs-plus/ntfs_corrupted_images.git"
REPO_NAME="ntfs_corrupted_images"
PWD=`pwd`
FSCK_PATH=$PWD/../src/
CHECKOUT_BR=${1:-"main"}

echo "Download corrupted images..."

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
	cd ..
else
	echo "Rebasing latest origin/main... "
	cd ${REPO_NAME} && git checkout main && git rebase origin/main
	RET=$?
	cd ..
fi

if [ $RET -ne 0 ]; then
	echo "Failed to checkout or rebase ${CHECKOUT_BR}"
	exit 1
fi

# test created_manually directory
echo "==============================================="
echo "Test corrupted images which is created manually"
echo "==============================================="
sleep 2
setsid /bin/bash -c "cd ${REPO_NAME}/created_manually && ENV=${FSCK_PATH} ./test_fsck.sh"
RET=$?
if [ $RET -ne 0 ]; then
	echo "Failed to test for created_manually images"
	exit 1
fi
echo "==================================================="
echo "Test corrupted images which is generated during use"
echo "==================================================="
sleep 2
# test generated_during_use directory
/bin/bash -c "cd ${REPO_NAME}/generated_during_use && ENV=${FSCK_PATH} ./test_fsck.sh"
if [ $? -ne 0 ]; then
	echo "Failed to test for generated_during_use images"
	exit 1
fi

if [ ${CHECKOUT_BR} != "main" ]; then
	echo "Delete working branch ${CHECKOUT_BR}... "
	setsid /bin/bash -c "cd ${REPO_NAME} && git branch -D ${CHECKOUT_BR}"
fi

#echo "==============================================="
#echo "Test for manually created images"
#echo "   Passed ${MAN_PASS_COUNT} of ${MAN_TOTAL_CNT}"
#echo
#echo "Test for generated images"
#echo "   Passed ${GEN_PASS_COUNT} of ${GEN_TOTAL_CNT}"
#echo "==============================================="
echo "Sucess to test corrupted images"
#rm -rf ${REPO_NAME}

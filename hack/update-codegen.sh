#!/usr/bin/env bash

set -x

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..
# Grab code-generator version from go.mod
CODEGEN_VERSION=$(grep 'k8s.io/code-generator' go.mod | awk '{print $2}')
CODEGEN_PKG=$(echo $(go env GOPATH)"/pkg/mod/k8s.io/code-generator@${CODEGEN_VERSION}")

if [[ ! -d ${CODEGEN_PKG} ]]; then
    echo "${CODEGEN_PKG} is missing. Running 'go mod download'."
    go mod download
fi

echo ">> Using ${CODEGEN_PKG}"
# Ensure we can execute.
chmod +x ${CODEGEN_PKG}/generate-groups.sh

# 注意:
# 1. kubebuilder2.3.2版本生成的api目录结构code-generator无法直接使用(将api由api/${VERSION}移动至api/${GROUP}/${VERSION}即可)

# corresponding to go mod init <module>
MODULE=github.com/driedmango520/kube-container-image
OUTPUT_PKG=pkg/client
GROUP=image.driedmango.io
VERSION=v1
GROUP_VERSION=${GROUP}:${VERSION}

#CODEGEN_PKG=${CODEGEN_PKG:-$(cd "${SCRIPT_ROOT}"; ls -d -1 ./vendor/k8s.io/code-generator 2>/dev/null || echo ../code-generator)}

rm -rf ${OUTPUT_PKG}/{clientset,informers,listers}

TEMP_DIR=$(mktemp -d)

cleanup() {
    echo ">> Removing ${TEMP_DIR}"
    rm -rf ${TEMP_DIR}
}
trap "cleanup" EXIT SIGINT

echo ">> Temporary output directory ${TEMP_DIR}"

cd ${SCRIPT_ROOT}
echo ${CODEGEN_PKG}
${CODEGEN_PKG}/generate-groups.sh "all" \
    ${MODULE}/${OUTPUT_PKG} ${MODULE}/api \
    ${GROUP_VERSION} \
    --output-base "${TEMP_DIR}" \
    -v 6 \
    --go-header-file hack/boilerplate.go.txt

# 检查 generate-groups.sh 执行是否成功
if [ $? -ne 0 ]; then
    echo "Error: generate-groups.sh failed."
    exit 1
fi

# Copy everything back.
cp -a "${TEMP_DIR}/${MODULE}/." "${SCRIPT_ROOT}/"

# 检查复制操作是否成功
if [ $? -ne 0 ]; then
    echo "Error: Copying files from temporary directory failed."
    exit 1
fi
#!/bin/bash -e
repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}")/../)
cd ${repo_root}

name=$(mktemp -u XXXXX)
pushd Docker
rm -rf tools
docker build --tag sgx_dcap_tools .
docker run  --name ${name} sgx_dcap_tools 
docker cp ${name}:/home/raoul/linux-sgx/SGXDataCenterAttestationPrimitives/tools/SGXPlatformRegistration/build/installer/ tools
rm tools/*dev*
rm tools/*dbgsym*
docker stop ${name}
popd

echo "Created DCAP platform registration tools in ${repo_root}/Docker/tools"

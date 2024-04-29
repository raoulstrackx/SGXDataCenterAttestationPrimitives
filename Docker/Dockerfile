From ubuntu:focal

RUN apt-get update
RUN DEBIAN_FRONTEND="noninteractive" TZ="America/New_York" apt-get install -y git build-essential python

# Install user
RUN useradd -rm -d /home/raoul -s /bin/bash -g root -G sudo -u 1000 raoul
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN echo 'raoul:raoul' | chpasswd
USER raoul
WORKDIR /home/raoul

# Install SGX Dev tools
USER root
RUN DEBIAN_FRONTEND="noninteractive" TZ="America/New_York" apt-get install -y build-essential ocaml ocamlbuild automake autoconf libtool wget python-is-python3 libssl-dev git cmake perl unzip libboost-dev libboost-system-dev libboost-thread-dev

USER raoul
RUN git clone https://github.com/intel/linux-sgx.git
WORKDIR linux-sgx
RUN make preparation
RUN ls external/toolset/
USER root
RUN cp external/toolset/ubuntu20.04/* /usr/local/bin
USER raoul
RUN make sdk
RUN make sdk_install_pkg
RUN ls linux/installer/bin

USER root
RUN apt-get install -y pkg-config
RUN bash -c "echo yes | ./$(find linux/installer/bin/ -name 'sgx_linux_x64_sdk*')"

# Install SGX DCAP primitives
USER root
RUN apt-get install -y protobuf-c-compiler libprotobuf-c-dev protobuf-compiler
RUN apt-get install -y libboost-dev libboost-system-dev
RUN apt-get install -y libcurl4-openssl-dev
USER raoul
RUN git clone https://github.com/intel/SGXDataCenterAttestationPrimitives.git
WORKDIR SGXDataCenterAttestationPrimitives
RUN git submodule update  --init
RUN source /home/raoul/linux-sgx/sgxsdk/environment && make

WORKDIR tools/PCKCertSelection
USER root
RUN apt-get install -y zip
USER raoul
RUN make

USER root
RUN apt-get install -y debhelper
USER raoul
WORKDIR ../../tools/SGXPlatformRegistration
RUN source /home/raoul/linux-sgx/sgxsdk/environment && make
RUN source /home/raoul/linux-sgx/sgxsdk/environment && make deb_pkg

# installed to:
# ~/linux-sgx/SGXDataCenterAttestationPrimitives/tools/SGXPlatformRegistration/build/installer/

ENTRYPOINT bash

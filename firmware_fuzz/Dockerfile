FROM jkjh1jkjh1/aflplusplus

RUN apt-get update
RUN apt-get install -y git

WORKDIR /AFLplusplus

# build afl++
COPY afl-common.c /AFLplusplus/src/afl-common.c
RUN STATIC=1 make distrib -j$(grep -c processor /proc/cpuinfo)

# build qemuafl
RUN rm -rf /AFLplusplus/qemuafl
COPY qemuafl /AFLplusplus/qemu_mode/

# build afl-qemu-trace for different architectures
RUN cd qemu_mode; NO_CHECKOUT=1 CPU_TARGET=x86_64 STATIC=1 ./build_qemu_support.sh
RUN mv afl-qemu-trace afl-qemu-trace-x86_64
#RUN cd qemu_mode; NO_CHECKOUT=1 CPU_TARGET=i386 STATIC=1 ./build_qemu_support.sh
#RUN mv afl-qemu-trace afl-qemu-trace-i386
#RUN cd qemu_mode; NO_CHECKOUT=1 CPU_TARGET=mips STATIC=1 ./build_qemu_support.sh
#RUN mv afl-qemu-trace afl-qemu-trace-mips
#RUN cd qemu_mode; NO_CHECKOUT=1 CPU_TARGET=mipsel STATIC=1 ./build_qemu_support.sh
#RUN mv afl-qemu-trace afl-qemu-trace-mipsel
#RUN cd qemu_mode; NO_CHECKOUT=1 CPU_TARGET=arm STATIC=1 ./build_qemu_support.sh
#RUN mv afl-qemu-trace afl-qemu-trace-arm
#RUN cd qemu_mode; NO_CHECKOUT=1 CPU_TARGET=armeb STATIC=1 ./build_qemu_support.sh
#RUN mv afl-qemu-trace afl-qemu-trace-armeb
#RUN cd qemu_mode; NO_CHECKOUT=1 CPU_TARGET=aarch64 STATIC=1 ./build_qemu_support.sh
#RUN mv afl-qemu-trace afl-qemu-trace-aarch64
RUN mkdir -p /AFLplusplus_release; PREFIX=/AFLplusplus_release make install
RUN mkdir /qemu; cp /AFLplusplus/afl-qemu-trace-* /qemu

CMD bash


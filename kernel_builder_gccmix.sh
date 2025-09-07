#!/bin/bash


GCC32="/tmp/optane/gcc/android_prebuilts_gcc_linux-x86_arm_arm-linux-androideabi-4.9-lineage-19.1"
export PATH="$PREFIX$GCC32/bin:$PATH"

export CROSS_COMPILE=arm-linux-androideabi-
export ARCH=arm
export SUBARCH=arm
export HEADER_ARCH=arm

#rm -rf out
mkdir out
rm -rf error.log
make O=out clean 
make mrproper

export CROSS_COMPILE=arm-linux-androideabi-
echo $PATH

cat arch/arm/configs/lineageos_i9300_defconfig > out/.config

make -j24 ARCH=arm O=out SUBARCH=arm O=out \
	CC="ccache arm-linux-androideabi-gcc -Wno-error" \
        LD="arm-linux-androideabi-ld.bfd" \
        AR="arm-linux-androideabi-ar" \
        AS="arm-linux-androideabi-as" \
        NM="arm-linux-androideabi-nm" \
        CROSS_COMPILE_ARM32="ccache arm-linux-androideabi-" \
        OBJCOPY="arm-linux-androideabi-objcopy" \
        OBJDUMP="arm-linux-androideabi-objdump" \
        STRIP="arm-linux-androideabi-strip" \
        CROSS_COMPILE="ccache arm-linux-androideabi-"
#echo $LD

# for i in $(ls patches_los16/) ; do patch -Np1 < patches_los16/$i ; done

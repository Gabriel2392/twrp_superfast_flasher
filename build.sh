set -e

CROSS=aarch64-linux-android34
LIBZ=aarch64-linux-android
NDK=android-ndk-r26d

aria2c -x 8 https://dl.google.com/android/repository/${NDK}-linux.zip
unzip -q ${NDK}-linux.zip
export PATH="$(pwd)/${NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin:${PATH}"

libbrotli="v1.1.0"
latest_libarchive=$(curl -s https://api.github.com/repos/libarchive/libarchive/releases/latest | jq -r '.tag_name')
latest_liblzma=$(curl -s https://api.github.com/repos/tukaani-project/xz/releases/latest | jq -r '.tag_name')
latest_libzstd=$(curl -s https://api.github.com/repos/facebook/zstd/releases/latest | jq -r '.tag_name')
latest_liblz4=$(curl -s https://api.github.com/repos/lz4/lz4/releases/latest | jq -r '.tag_name')
if [ "$latest_libarchive" == "null" ] || [ "$latest_libzstd" == "null" ] || [ "$latest_liblzma" == "null" ] || [ "$latest_liblz4" == "null" ]; then
  exit 1
fi

echo "libarchive $latest_libarchive"
echo "liblzma $latest_liblzma"
echo "libzstd $latest_libzstd"
echo "liblz4 $latest_liblz4"
echo "libbrotli $libbrotli"

wget https://github.com/libarchive/libarchive/releases/download/${latest_libarchive}/libarchive-${latest_libarchive//v/}.tar.gz -O - -o /dev/null | tar -xz
wget https://github.com/facebook/zstd/releases/download/${latest_libzstd}/zstd-${latest_libzstd//v/}.tar.gz -O - -o /dev/null | tar -xz
wget https://github.com/tukaani-project/xz/releases/download/${latest_liblzma}/xz-${latest_liblzma//v/}.tar.gz -O - -o /dev/null | tar -xz
wget https://github.com/lz4/lz4/releases/download/${latest_liblz4}/lz4-${latest_liblz4//v/}.tar.gz -O - -o /dev/null | tar -xz
git clone https://github.com/google/brotli -b $libbrotli --depth=1

DIR="$(pwd)"

# archive
cd "libarchive-${latest_libarchive//v/}"
libarchive="$(pwd)"
./configure --without-xml2 --without-expat --without-openssl --without-cng --without-lzma --without-zstd --without-lz4 --without-iconv --without-bz2lib --without-libb2 --disable-bsdcpio --disable-bsdcat --disable-bsdtar --disable-bsdunzip --enable-shared=no --host=${CROSS} CC=${CROSS}-clang CXX=${CROSS}-clang++ CFLAGS=-I./contrib/android/include 
make -j2
cd "$DIR"

# brotli
cd brotli
libbrotli="$(pwd)"
mkdir build
cd build
cmake .. -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_COMPILER=${CROSS}-clang -DCMAKE_CXX_COMPILER=${CROSS}-clang++
make -j2
cd "$DIR"

# zstd
cd "zstd-${latest_libzstd//v/}"
libzstd="$(pwd)"
make CC=${CROSS}-clang CXX=${CROSS}-clang++ -j2
cd "$DIR"

# lz4
cd "lz4-${latest_liblz4//v/}"
liblz4="$(pwd)"
make CC=${CROSS}-clang CXX=${CROSS}-clang++ -j2
cd "$DIR"

# lzma
cd "xz-${latest_liblzma//v/}"
liblzma="$(pwd)"
./autogen.sh || true
./configure --enable-shared=no CC=${CROSS}-clang CXX=${CROSS}-clang++ --disable-doc --host=${CROSS}
make -j2
cd "$DIR"

cp ${libarchive}/.libs/libarchive.a .
cp ${libzstd}/lib/libzstd.a .
cp ${liblzma}/src/liblzma/.libs/liblzma.a .
cp ${liblz4}/lib/liblz4.a .
cp ${libbrotli}/build/libbrotlidec.a .
cp ${libbrotli}/build/libbrotlicommon.a .
cp $NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/${LIBZ}/libz.a .

${CROSS}-clang++ *.cpp -o update-binary -O3 -std=c++20 -static -s -L. -lbrotlicommon -lbrotlidec -larchive -lzstd -lz -llzma -llz4 -static-libstdc++ -I${libbrotli}/c/include -I${libarchive}/libarchive -I${liblz4}/lib -I${libzstd}/lib -Wall -Wextra -llzma -I${liblzma}/src/liblzma/api

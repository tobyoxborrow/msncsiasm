LIB_DIR=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

default: msncsi.nasm
	nasm -f macho64 -o msncsi.o msncsi.nasm
	ld -macosx_version_min 12.4 -L$(LIB_DIR) -lSystem -no_pie -o msncsi msncsi.o
osx: msncsi.nasm
	nasm -f macho64 -o msncsi.o msncsi.nasm
	ld -macosx_version_min 10.9 -lSystem -o msncsi msncsi.o
byteswap: byteswap.nasm
	nasm -f macho64 -o byteswap.o byteswap.nasm
	ld -macosx_version_min 12.4 -L$(LIB_DIR) -lSystem -o byteswap byteswap.o
byteswapip: byteswapip.nasm
	nasm -f macho64 -o byteswapip.o byteswapip.nasm
	ld -macosx_version_min 12.4 -L$(LIB_DIR) -lSystem -o byteswapip byteswapip.o
clean:
	rm msncsi msncsi.o \
		byteswap byteswap.o \
		byteswapip byteswapip.o \

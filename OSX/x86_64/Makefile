default: msncsi.nasm
	nasm -f macho64 -o msncsi.o msncsi.nasm
	ld -macosx_version_min 10.9 -lSystem -o msncsi msncsi.o
byteswap: byteswap.nasm
	nasm -f macho64 -o byteswap.o byteswap.nasm
	ld -macosx_version_min 10.9 -lSystem -o byteswap byteswap.o
byteswapip: byteswapip.nasm
	nasm -f macho64 -o byteswapip.o byteswapip.nasm
	ld -macosx_version_min 10.9 -lSystem -o byteswapip byteswapip.o
clean:
	rm msncsi msncsi.o \
		byteswap byteswap.o \
		byteswapip byteswapip.o \

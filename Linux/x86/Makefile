default: msncsi.nasm
	nasm -f elf32 -o msncsi.o msncsi.nasm
	ld -m elf_i386 -o msncsi msncsi.o
byteswap: byteswap.nasm
	nasm -f elf32 -o byteswap.o byteswap.nasm
	ld -m elf_i386 -o byteswap byteswap.o
byteswapip: byteswapip.nasm
	nasm -f elf32 -o byteswapip.o byteswapip.nasm
	ld -m elf_i386 -o byteswapip byteswapip.o
clean:
	rm msncsi msncsi.o \
		byteswap byteswap.o \
		byteswapip byteswapip.o \
